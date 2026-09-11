/*
 * t1.c
 * Apple T1 / iBridge1,1 (x619ap) EmbeddedOS support for idevicerestore.
 *
 * PROTOCOL NOTES
 * --------------
 * The T1 has no firmware in ROM. macOS stages a personalized image on the EFI
 * System Partition at EFI/APPLE/EMBEDDEDOS/combined.memboot and Apple's boot
 * firmware memboots it into the chip on every power-on. Erase the ESP and the
 * T1 comes up in recovery (05ac:1281) instead of production iBridge mode
 * (05ac:8600), taking the Touch Bar, webcam, ALS and Touch ID with it.
 *
 * Recovering it without macOS is a three-step dance:
 *
 *   Pass A  restore once with FDR *output* armed, to make the T1 generate
 *           device-specific FDRData that did not previously exist.
 *   FRST    T1-only reset back to recovery.
 *   Pass B  restore again with that FDRData replayed as *input*, capturing the
 *           personalized combined memboot image AND the AP ticket from the very
 *           same TSS/preflight transaction.
 *   FRST    reset back to recovery.
 *   Phase14 replay exactly that image + ticket pair via a blind memboot.
 *
 * The image and ticket MUST come from one transaction. Requesting a fresh
 * ticket after FRST produces correctly-signed-looking images that the T1
 * rejects, dropping straight back to 05ac:1281.
 *
 * combined.memboot for this Image4-capable part is a bare concatenation, in
 * order, with no 2GMI wrapper, no alignment padding and no rewritten sizes:
 *
 *     OSRamdisk (osrd) || KernelCache (krnl) || DeviceTree (dtre) || SEP (sepi)
 *
 * PRIVACY
 * -------
 * FDR stores, AP tickets and personalized images carry a specific chip's
 * provisioning identity. They are written 0600 and never logged. Nothing here
 * prints ticket bytes, nonces, ECIDs or FDR contents; only sizes and key names.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>

#include <libirecovery.h>
#include <libtatsu/tss.h>

#include "t1.h"
#include "common.h"
#include "idevicerestore.h"
#include "recovery.h"
#include "restore.h"

/* Components of the combined memboot, in concatenation order. Deliberately the
 * plain variants: the Restore* ones are a known-failed substitution. */
static const char *k_memboot_components[] = {
	"OSRamdisk", "KernelCache", "DeviceTree", "SEP"
};
#define T1_MEMBOOT_COMPONENT_COUNT 4

/* ------------------------------------------------------------------------- */
/* switches                                                                   */
/* ------------------------------------------------------------------------- */

const char *t1_env(const char *name)
{
	const char *v = getenv(name);
	if (!v || !*v) return NULL;
	return v;
}

int t1_flag(const char *name)
{
	const char *v = t1_env(name);
	if (!v) return 0;
	if (!strcmp(v, "0") || !strcmp(v, "false") || !strcmp(v, "no")) return 0;
	return 1;
}

int t1_embeddedos_enabled(void) { return t1_flag(T1_ENV_EMBEDDEDOS); }
int t1_phase14_enabled(void)    { return t1_flag(T1_ENV_PHASE14); }

/* ------------------------------------------------------------------------- */
/* private file I/O                                                           */
/* ------------------------------------------------------------------------- */

/* Write buf to path atomically at mode 0600: temp file in the same directory,
 * fsync, rename. Never partially overwrites a good artefact. */
static int t1_write_private(const char *path, const void *buf, size_t len)
{
	char tmp[4096];
	int fd, rc = -1;

	if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp)) {
		logger(LL_ERROR, "T1: destination path too long\n");
		return -1;
	}

	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		logger(LL_ERROR, "T1: cannot create private file (%s)\n", strerror(errno));
		return -1;
	}
	if (fchmod(fd, S_IRUSR | S_IWUSR) != 0) {
		logger(LL_ERROR, "T1: cannot set 0600 (%s)\n", strerror(errno));
		goto out;
	}

	{
		const unsigned char *p = (const unsigned char *)buf;
		size_t left = len;
		while (left) {
			ssize_t n = write(fd, p, left);
			if (n < 0) {
				if (errno == EINTR) continue;
				logger(LL_ERROR, "T1: write failed (%s)\n", strerror(errno));
				goto out;
			}
			p += n; left -= (size_t)n;
		}
	}
	if (fsync(fd) != 0) {
		logger(LL_ERROR, "T1: fsync failed (%s)\n", strerror(errno));
		goto out;
	}
	close(fd); fd = -1;

	if (rename(tmp, path) != 0) {
		logger(LL_ERROR, "T1: rename failed (%s)\n", strerror(errno));
		goto out;
	}
	rc = 0;

out:
	if (fd >= 0) close(fd);
	if (rc != 0) unlink(tmp);
	return rc;
}

static int t1_read_file(const char *path, void **out, size_t *out_len)
{
	FILE *f = fopen(path, "rb");
	long sz;
	void *buf;

	*out = NULL; *out_len = 0;
	if (!f) {
		logger(LL_ERROR, "T1: cannot open '%s' (%s)\n", path, strerror(errno));
		return -1;
	}
	if (fseek(f, 0, SEEK_END) != 0 || (sz = ftell(f)) < 0) {
		fclose(f); return -1;
	}
	rewind(f);
	buf = malloc((size_t)sz);
	if (!buf) { fclose(f); return -1; }
	if (sz > 0 && fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
		free(buf); fclose(f); return -1;
	}
	fclose(f);
	*out = buf; *out_len = (size_t)sz;
	return 0;
}

/* ------------------------------------------------------------------------- */
/* restore option / data-type hooks                                           */
/* ------------------------------------------------------------------------- */

void t1_apply_restore_options(plist_t opts)
{
	if (!t1_embeddedos_enabled() || !opts) return;

	/* An EmbeddedOS restore installs firmware only. It must not carry a host
	 * system image, must not create filesystem partitions, and must not be
	 * bootstrap-only (that variant never reaches the phase-11 we need). */
	plist_dict_set_item(opts, "ApBootstrapOnly",           plist_new_bool(0));
	plist_dict_set_item(opts, "PersonalizedDuringPreflight", plist_new_bool(1));
	plist_dict_set_item(opts, "FlashNOR",                  plist_new_bool(1));
	plist_dict_set_item(opts, "ShouldRestoreSystemImage",  plist_new_bool(0));
	/* Default off, per the gist. On a T1 whose NAND was never provisioned this
	 * has to be on, or restored cannot create its FDR data storage
	 * ("Could not mkdir (Read-only file system)") and fdr_recover fails. */
	plist_dict_set_item(opts, "CreateFilesystemPartitions",
	                    plist_new_bool(t1_flag(T1_ENV_CREATE_PARTITIONS) ? 1 : 0));
	if (t1_flag(T1_ENV_CREATE_PARTITIONS)) {
		logger(LL_INFO, "T1: CreateFilesystemPartitions ENABLED (deviates from the gist)\n");
	}
	plist_dict_set_item(opts, "SystemImage",               plist_new_bool(0));
	plist_dict_set_item(opts, "RootToInstall",             plist_new_bool(0));
	plist_dict_set_item(opts, "UpdateBaseband",            plist_new_bool(0));

	/* FDR memory store: on by default in EmbeddedOS mode. See t1.h. */
	{
		const char *ms = t1_env(T1_ENV_FDR_MEMSTORE);
		if (!ms) ms = T1_FDR_MEMSTORE_DEFAULT;
		if (strcmp(ms, "0") != 0) {
			plist_dict_set_item(opts, "FDRMemoryStorePath", plist_new_string(ms));
			logger(LL_INFO, "T1: FDRMemoryStorePath = %s\n", ms);
		} else {
			logger(LL_INFO, "T1: FDR memory store DISABLED by env\n");
		}
	}

	/* Phase-14-only key; must not appear in a phase-11 transaction. */
	plist_dict_remove_item(opts, "BootImageTagOverride");

	/* The recovery boot args must carry both -restore and standardMuxOnly, or
	 * restored never enters the phase we need. This runs after upstream's own
	 * RestoreBootArgs write, so it wins. */
	{
		const char *ba = t1_env(T1_ENV_BOOT_ARGS);
		if (ba) {
			plist_dict_set_item(opts, "RestoreBootArgs", plist_new_string(ba));
			logger(LL_INFO, "T1: RestoreBootArgs overridden from %s\n", T1_ENV_BOOT_ARGS);
		}
	}

	logger(LL_INFO, "T1: EmbeddedOS restore options applied\n");
}

void t1_apply_supported_data_types(plist_t dict)
{
	if (!dict) return;
	if (!t1_env(T1_ENV_FDR_OUTPUT)) return;

	/* Upstream advertises FDRMemoryCommit as unsupported. The T1 EmbeddedOS
	 * restore will not complete unless the host both accepts and acks it. */
	plist_dict_set_item(dict, "FDRMemoryCommit", plist_new_bool(1));
	logger(LL_INFO, "T1: advertising FDRMemoryCommit support\n");
}

/* Log the shape of a message without disclosing any value. */
static void t1_log_message_shape(plist_t message, const char *what)
{
	plist_dict_iter it = NULL;
	char *key = NULL;
	plist_t val = NULL;

	if (!message || plist_get_node_type(message) != PLIST_DICT) return;

	logger(LL_INFO, "T1: %s message shape:\n", what);
	plist_dict_new_iter(message, &it);
	if (!it) return;
	do {
		plist_dict_next_item(message, it, &key, &val);
		if (!key) break;
		const char *type = "?";
		uint64_t sz = 0;
		switch (plist_get_node_type(val)) {
			case PLIST_DICT:   type = "dict";   sz = plist_dict_get_size(val); break;
			case PLIST_ARRAY:  type = "array";  sz = plist_array_get_size(val); break;
			case PLIST_DATA:   type = "data";   plist_get_data_val(val, NULL, &sz); break;
			case PLIST_STRING: type = "string"; break;
			case PLIST_BOOLEAN:type = "bool";   break;
			case PLIST_INT:    type = "int";    break;
			default: break;
		}
		logger(LL_INFO, "T1:   %s : %s (%llu)\n", key, type, (unsigned long long)sz);
		free(key); key = NULL;
	} while (1);
	free(it);
}

/* Find the FDR payload inside a FDRMemoryCommit message. Apple has used more
 * than one key name here across builds, so try the known ones and otherwise
 * fall back to the sole data/dict member. */
static plist_t t1_find_fdr_payload(plist_t message)
{
	static const char *candidates[] = {
		"FDRMemoryStoreData", "FDRMemoryCommitData", "FDRData",
		"MemoryStoreData", "Data", NULL
	};
	int i;
	if (!message || plist_get_node_type(message) != PLIST_DICT) return NULL;

	plist_t args;
	for (i = 0; candidates[i]; i++) {
		plist_t n = plist_dict_get_item(message, candidates[i]);
		if (n) {
			plist_type t = plist_get_node_type(n);
			if (t == PLIST_DATA || t == PLIST_DICT) {
				logger(LL_INFO, "T1: FDR payload found under '%s'\n", candidates[i]);
				return n;
			}
		}
	}

	/* Observed on the real device: the store arrives wrapped as
	 *   { DataType, MsgType, Arguments: { <one key>: <store> } }
	 * so look one level down inside Arguments as well. */
	args = plist_dict_get_item(message, "Arguments");
	if (args && plist_get_node_type(args) == PLIST_DICT) {
		t1_log_message_shape(args, "FDRMemoryCommit.Arguments");
		for (i = 0; candidates[i]; i++) {
			plist_t n = plist_dict_get_item(args, candidates[i]);
			if (n && (plist_get_node_type(n) == PLIST_DATA || plist_get_node_type(n) == PLIST_DICT)) {
				logger(LL_INFO, "T1: FDR payload found under 'Arguments.%s'\n", candidates[i]);
				return n;
			}
		}
		if (plist_dict_get_size(args) == 1) {
			plist_dict_iter it = NULL; char *k = NULL; plist_t v = NULL;
			plist_dict_new_iter(args, &it);
			if (it) { plist_dict_next_item(args, it, &k, &v); free(it); }
			if (v && (plist_get_node_type(v) == PLIST_DATA || plist_get_node_type(v) == PLIST_DICT)) {
				logger(LL_INFO, "T1: FDR payload is the sole Arguments member '%s'\n", k ? k : "?");
				free(k);
				return v;
			}
			free(k);
		}
	}
	return NULL;
}

int t1_handle_fdr_memory_commit(struct idevicerestore_client_t *client, plist_t message)
{
	const char *out_path = t1_env(T1_ENV_FDR_OUTPUT);
	plist_t payload = NULL;
	char *bin = NULL;
	uint32_t bin_len = 0;

	if (!out_path) return 1; /* not armed - caller handles */

	logger(LL_INFO, "T1: FDRMemoryCommit received\n");
	t1_log_message_shape(message, "FDRMemoryCommit");

	payload = t1_find_fdr_payload(message);
	if (!payload) {
		/* Persist the whole message rather than lose the transaction; the
		 * shape log above tells us which key to promote next time. */
		logger(LL_WARNING, "T1: no known FDR payload key; saving whole message\n");
		payload = message;
	}

	if (plist_get_node_type(payload) == PLIST_DATA) {
		uint64_t len = 0;
		char *raw = NULL;
		plist_get_data_val(payload, &raw, &len);
		if (!raw) return -1;
		if (t1_write_private(out_path, raw, (size_t)len) != 0) { free(raw); return -1; }
		logger(LL_INFO, "T1: FDR store saved (%llu bytes, mode 0600)\n",
		       (unsigned long long)len);
		free(raw);
		return 0;
	}

	plist_to_bin(payload, &bin, &bin_len);
	if (!bin) {
		logger(LL_ERROR, "T1: could not serialize FDR store\n");
		return -1;
	}
	if (t1_write_private(out_path, bin, bin_len) != 0) { free(bin); return -1; }
	logger(LL_INFO, "T1: FDR store saved (%u bytes, binary plist, mode 0600)\n", bin_len);
	free(bin);
	return 0;
}

void t1_augment_root_ticket(plist_t dict)
{
	const char *in_path = t1_env(T1_ENV_FDR_INPUT);
	void *buf = NULL;
	size_t len = 0;
	plist_t fdr = NULL;

	if (!in_path || !dict) return;

	if (t1_read_file(in_path, &buf, &len) != 0) {
		logger(LL_ERROR, "T1: cannot read FDR input\n");
		return;
	}

	/* The store round-trips as a binary plist; replay it as the same node type
	 * it was committed as, so Pass B's FDRData.replayed compares byte-identical
	 * to Pass A's FDRData. */
	plist_from_memory((const char *)buf, (uint32_t)len, &fdr, NULL);
	if (fdr) {
		plist_dict_set_item(dict, "FDRMemoryStoreData", fdr);
		logger(LL_INFO, "T1: replaying FDR store into RootTicket (%zu bytes, plist)\n", len);
	} else {
		plist_dict_set_item(dict, "FDRMemoryStoreData", plist_new_data((char *)buf, len));
		logger(LL_INFO, "T1: replaying FDR store into RootTicket (%zu bytes, data)\n", len);
	}
	free(buf);
}

/* ------------------------------------------------------------------------- */
/* firmware-bundle compatibility                                              */
/* ------------------------------------------------------------------------- */

static unsigned int t1_plist_uint(plist_t d, const char *key)
{
	plist_t n = plist_dict_get_item(d, key);
	uint64_t v = 0;
	if (!n) return 0xffffffffu;
	if (plist_get_node_type(n) == PLIST_INT) {
		plist_get_uint_val(n, &v);
		return (unsigned int)v;
	}
	if (plist_get_node_type(n) == PLIST_STRING) {
		const char *sv = plist_get_string_ptr(n, NULL);
		if (sv) return (unsigned int)strtoul(sv, NULL, 0);
	}
	return 0xffffffffu;
}

int t1_manifest_matches_device(plist_t build_manifest, unsigned int chip_id, unsigned int board_id)
{
	plist_t identities;
	uint32_t n, i;

	if (!t1_embeddedos_enabled()) return -1;
	if (!build_manifest) return 0;

	/* A bundle that DOES declare SupportedProductTypes is an ordinary IPSW;
	 * leave it to the normal check rather than loosening anything. */
	if (plist_dict_get_item(build_manifest, "SupportedProductTypes")) return -1;

	identities = plist_dict_get_item(build_manifest, "BuildIdentities");
	if (!identities || plist_get_node_type(identities) != PLIST_ARRAY) {
		logger(LL_ERROR, "T1: manifest has no BuildIdentities\n");
		return 0;
	}

	n = plist_array_get_size(identities);
	for (i = 0; i < n; i++) {
		plist_t bi = plist_array_get_item(identities, i);
		unsigned int mchip, mboard;
		if (!bi || plist_get_node_type(bi) != PLIST_DICT) continue;
		mchip  = t1_plist_uint(bi, "ApChipID");
		mboard = t1_plist_uint(bi, "ApBoardID");
		if (mchip == chip_id && mboard == board_id) {
			plist_t info = plist_dict_get_item(bi, "Info");
			const char *dc = NULL, *variant = NULL;
			if (info) {
				plist_t d = plist_dict_get_item(info, "DeviceClass");
				plist_t v = plist_dict_get_item(info, "Variant");
				if (d) dc = plist_get_string_ptr(d, NULL);
				if (v) variant = plist_get_string_ptr(v, NULL);
			}
			logger(LL_INFO, "T1: manifest matches this device: ApChipID 0x%04x, ApBoardID 0x%02x, DeviceClass %s, Variant '%s'\n",
			       mchip, mboard, dc ? dc : "?", variant ? variant : "?");
			return 1;
		}
	}

	logger(LL_ERROR, "T1: no BuildIdentity in this manifest matches ApChipID 0x%04x / ApBoardID 0x%02x\n",
	       chip_id, board_id);
	return 0;
}

void t1_augment_fdr_trust_data(plist_t reply, plist_t request)
{
	if (!t1_embeddedos_enabled()) return;
	t1_log_message_shape(request, "FDRTrustData request");
	if (!reply) return;
	if (t1_flag(T1_ENV_FDR_TRUST_KEY)) {
		plist_dict_set_item(reply, "FDRTrustData", plist_new_data("", 0));
		logger(LL_INFO, "T1: replying to FDRTrustData WITH the FDRTrustData key (empty data)\n");
	} else {
		logger(LL_INFO, "T1: replying to FDRTrustData with upstream's empty dict\n");
	}
}

/* ------------------------------------------------------------------------- */
/* preflight capture                                                          */
/* ------------------------------------------------------------------------- */

int t1_save_preflight(struct idevicerestore_client_t *client, plist_t build_identity, plist_t tss)
{
	const char *memboot_path = t1_env(T1_ENV_PREFLIGHT_MEMBOOT);
	const char *ticket_path  = t1_env(T1_ENV_PREFLIGHT_TICKET);
	unsigned char *ticket = NULL;
	unsigned int ticket_len = 0;
	unsigned char *combined = NULL;
	size_t combined_len = 0;
	int i, rc = -1;

	if (!memboot_path && !ticket_path) return 0; /* not armed */
	if (!client || !build_identity || !tss) {
		logger(LL_ERROR, "T1: preflight capture called without a TSS response\n");
		return -1;
	}

	logger(LL_INFO, "T1: capturing preflight artefacts\n");

	/* 1. The AP ticket from THIS TSS response. Phase 14 must replay this exact
	 *    ticket alongside the image built below. */
	if (ticket_path) {
		if (tss_response_get_ap_img4_ticket(tss, &ticket, &ticket_len) < 0) {
			logger(LL_ERROR, "T1: no ApImg4Ticket in TSS response\n");
			goto out;
		}
		if (t1_write_private(ticket_path, ticket, ticket_len) != 0) goto out;
		logger(LL_INFO, "T1: AP ticket saved (%u bytes, mode 0600)\n", ticket_len);
	}

	/* 2. The four personalized components, concatenated bare. */
	if (memboot_path) {
		for (i = 0; i < T1_MEMBOOT_COMPONENT_COUNT; i++) {
			const char *name = k_memboot_components[i];
			char *path = NULL;
			void *raw = NULL, *personalized = NULL;
			size_t raw_len = 0, p_len = 0;
			unsigned char *grown;

			if (build_identity_get_component_path(build_identity, name, &path) < 0) {
				logger(LL_ERROR, "T1: no path for component '%s'\n", name);
				goto out;
			}
			if (extract_component(client->ipsw, path, &raw, &raw_len) < 0) {
				logger(LL_ERROR, "T1: cannot extract '%s'\n", name);
				free(path);
				goto out;
			}
			free(path);

			if (personalize_component(client, name, raw, raw_len, tss,
			                          &personalized, &p_len) < 0) {
				logger(LL_ERROR, "T1: cannot personalize '%s'\n", name);
				free(raw);
				goto out;
			}
			free(raw);

			grown = realloc(combined, combined_len + p_len);
			if (!grown) { free(personalized); goto out; }
			combined = grown;
			memcpy(combined + combined_len, personalized, p_len);
			combined_len += p_len;
			free(personalized);

			logger(LL_INFO, "T1:   %-12s personalized, %zu bytes\n", name, p_len);
		}

		if (t1_write_private(memboot_path, combined, combined_len) != 0) goto out;
		logger(LL_INFO, "T1: combined memboot saved (%zu bytes, mode 0600)\n", combined_len);
	}

	rc = 0;
out:
	free(ticket);
	free(combined);
	return rc;
}

/* ------------------------------------------------------------------------- */
/* phase 14                                                                   */
/* ------------------------------------------------------------------------- */

int t1_phase14(struct idevicerestore_client_t *client)
{
	const char *memboot_path = t1_env(T1_ENV_MEMBOOT_FILE);
	const char *ticket_path  = t1_env(T1_ENV_APTICKET_FILE);
	const char *boot_args    = t1_env(T1_ENV_BOOT_ARGS);
	void *image = NULL, *ticket = NULL;
	size_t image_len = 0, ticket_len = 0;
	irecv_error_t err;
	int rc = -1;

	if (!memboot_path || !ticket_path) {
		logger(LL_ERROR, "T1: phase 14 needs both %s and %s\n",
		       T1_ENV_MEMBOOT_FILE, T1_ENV_APTICKET_FILE);
		return -1;
	}

	/* Modes this build deliberately does not implement. The 2GMI container in
	 * particular is a known-failed approach on this Image4 part. Refuse loudly
	 * rather than silently ignoring a switch the operator believes is active. */
	{
		static const char *unimplemented[] = {
			"IDEVICERESTORE_MEMBOOT_2GMI",
			"IDEVICERESTORE_MEMBOOT_EXACT",
			"IDEVICERESTORE_MEMBOOT_SAVE",
			"IDEVICERESTORE_OSRAMDISK_SEPARATE",
			NULL
		};
		int i, bad = 0;
		for (i = 0; unimplemented[i]; i++) {
			if (t1_env(unimplemented[i])) {
				logger(LL_ERROR, "T1: %s is set but not implemented by this build\n",
				       unimplemented[i]);
				bad = 1;
			}
		}
		if (bad) {
			logger(LL_ERROR, "T1: refusing phase 14 rather than ignoring it. Unset and retry.\n");
			return -1;
		}
	}

	/* Advisory in this build: phase 14 replays the captured file verbatim, so
	 * the image is whatever Pass B produced - an OS-image memboot by
	 * construction. Warn if the operator expected otherwise. */
	if (!t1_flag(T1_ENV_OSRAMDISK) || !t1_flag(T1_ENV_MEMBOOT_OS_IMAGE)) {
		logger(LL_WARNING, "T1: %s / %s not both set; replaying the captured image verbatim anyway\n",
		       T1_ENV_OSRAMDISK, T1_ENV_MEMBOOT_OS_IMAGE);
	}

	if (!boot_args) boot_args = "rd=md0";

	if (t1_read_file(memboot_path, &image, &image_len) != 0) goto out;
	if (t1_read_file(ticket_path, &ticket, &ticket_len) != 0) goto out;
	logger(LL_INFO, "T1: phase 14 - image %zu bytes, ticket %zu bytes\n",
	       image_len, ticket_len);

	if (!client->recovery && recovery_client_new(client) < 0) {
		logger(LL_ERROR, "T1: no device in recovery mode (expected 05ac:1281)\n");
		goto out;
	}

	/* auto-boot=false + saveenv BEFORE the ticket. Omitting this is a known
	 * failure: the part comes back up in recovery. */
	if (recovery_set_autoboot(client, 0) < 0) {
		logger(LL_ERROR, "T1: could not clear auto-boot\n");
		goto out;
	}

	/* Send the saved AP ticket - never a freshly requested one. */
	err = irecv_send_buffer(client->recovery->client, ticket, ticket_len, 0);
	if (err != IRECV_E_SUCCESS) {
		logger(LL_ERROR, "T1: ticket upload failed (%d)\n", err);
		goto out;
	}
	err = irecv_send_command(client->recovery->client, "ticket");
	if (err != IRECV_E_SUCCESS) {
		logger(LL_ERROR, "T1: 'ticket' command failed (%d)\n", err);
		goto out;
	}

	/* Upload the exact preflight image. */
	err = irecv_send_buffer(client->recovery->client, image, image_len, 0);
	if (err != IRECV_E_SUCCESS) {
		logger(LL_ERROR, "T1: image upload failed (%d)\n", err);
		goto out;
	}

	{
		char setba[256];
		snprintf(setba, sizeof(setba), "setenv boot-args %s", boot_args);
		err = irecv_send_command(client->recovery->client, setba);
		if (err != IRECV_E_SUCCESS) {
			logger(LL_ERROR, "T1: setting boot-args failed (%d)\n", err);
			goto out;
		}
	}

	/* Blind memboot: bRequest=1, no reply expected. Apple's later EFI memboot
	 * helper uses bRequest=0 with a normal command; that variant fails here. */
	logger(LL_INFO, "T1: issuing blind memboot (bRequest=1)\n");
	irecv_send_command_breq(client->recovery->client, "memboot", 1);

	logger(LL_INFO, "T1: phase 14 transaction dispatched.\n");
	logger(LL_INFO, "T1: this does NOT mean the image was accepted - watch USB\n");
	logger(LL_INFO, "T1: for a stable 05ac:8600 for at least 30 seconds.\n");
	rc = 0;

out:
	free(image);
	free(ticket);
	return rc;
}
