/*
 * t1.h
 * Apple T1 / iBridge1,1 (x619ap) EmbeddedOS support for idevicerestore.
 *
 * Everything here is opt-in and guarded by environment variables. With none of
 * them set, every entry point below is a no-op and idevicerestore behaves
 * exactly as upstream. See t1.c for the protocol notes.
 */

#ifndef T1_H
#define T1_H

#include <plist/plist.h>
#include "common.h"

/* --- opt-in switches ------------------------------------------------------ */
#define T1_ENV_EMBEDDEDOS        "IDEVICERESTORE_T1_EMBEDDEDOS"
#define T1_ENV_FDR_INPUT         "IDEVICERESTORE_T1_FDR_INPUT"
#define T1_ENV_FDR_OUTPUT        "IDEVICERESTORE_T1_FDR_OUTPUT"
#define T1_ENV_BOOT_ARGS         "IDEVICERESTORE_RESTORE_BOOT_ARGS"
#define T1_ENV_PREFLIGHT_MEMBOOT "IDEVICERESTORE_T1_PREFLIGHT_MEMBOOT_SAVE"
#define T1_ENV_PREFLIGHT_TICKET  "IDEVICERESTORE_T1_PREFLIGHT_TICKET_SAVE"
#define T1_ENV_PHASE14           "IDEVICERESTORE_T1_PHASE14"
#define T1_ENV_MEMBOOT_FILE      "IDEVICERESTORE_MEMBOOT_FILE"
#define T1_ENV_APTICKET_FILE     "IDEVICERESTORE_T1_APTICKET_FILE"
#define T1_ENV_OSRAMDISK         "IDEVICERESTORE_OSRAMDISK"
#define T1_ENV_MEMBOOT_OS_IMAGE  "IDEVICERESTORE_MEMBOOT_OS_IMAGE"
/* Let the restore create/mount the T1's own filesystem partitions. The gist
 * keeps this off, but on a T1 whose NAND has never been provisioned restored
 * cannot persist FDR data ("System partition is not mounted" / read-only fs)
 * and fdr_recover then fails. Tri-state: unset = gist default (off). */
#define T1_ENV_CREATE_PARTITIONS "IDEVICERESTORE_T1_CREATE_PARTITIONS"
/* Answer the FDRTrustData request with the FDRTrustData key present (empty
 * data) instead of upstream's empty dict. The device logs "Received response
 * without expected RESTORED_FDR_TRUST_DATA" for the empty dict and then takes
 * the local-storage branch, which fails on a T1 with no writable fs. */
#define T1_ENV_FDR_TRUST_KEY     "IDEVICERESTORE_T1_FDR_TRUST_KEY"
/* Device-side path for restored's FDR memory store. The T1 restore ramdisk
 * has no mountable system partition, so without a memory store restored
 * logs "System partition is not mounted, not able to preserve FDR data" and
 * fdr_recover fails. With it, restored flushes FDR state to this path and
 * commits it to the host via the FDRMemoryCommit data request - which is
 * what our FDR output handler exists to receive. Set to "0" to disable. */
#define T1_ENV_FDR_MEMSTORE      "IDEVICERESTORE_T1_FDR_MEMSTORE_PATH"
#define T1_FDR_MEMSTORE_DEFAULT  "/tmp/FDRMemoryStore"

/* True when the named switch is set to a non-empty, non-"0" value. */
int t1_flag(const char *name);
/* Value of the named switch, or NULL. Never logged. */
const char *t1_env(const char *name);

/* Master switches. */
int t1_embeddedos_enabled(void);
int t1_phase14_enabled(void);

/* --- restore-time hooks --------------------------------------------------- */

/* Apply the EmbeddedOS restore options to the StartRestore options dict:
 * no host system image, no partition creation, not bootstrap-only. */
void t1_apply_restore_options(plist_t opts);

/* Mark FDRMemoryCommit supported when FDR output is armed. */
void t1_apply_supported_data_types(plist_t dict);

/* Handle a FDRMemoryCommit data request: persist the FDR store and ack.
 * Returns 0 on success, -1 on failure, and 1 if not armed (caller falls
 * through to its own handling). */
int t1_handle_fdr_memory_commit(struct idevicerestore_client_t *client, plist_t message);

/* Add FDRMemoryStoreData to an outgoing RootTicket dict when FDR input is
 * armed. No-op otherwise. */
void t1_augment_root_ticket(plist_t dict);

/* Capture the personalized preflight artefacts: the four-component bare
 * concatenation (OSRamdisk, KernelCache, DeviceTree, SEP) and the AP ticket
 * from the SAME TSS response. Both must come from one transaction; phase 14
 * replays exactly this pair. No-op unless the save paths are armed. */
int t1_save_preflight(struct idevicerestore_client_t *client, plist_t build_identity, plist_t tss);

/* Compatibility check for an Apple firmware BUNDLE rather than an IPSW.
 * iBridge1_1Customer.bundle carries no SupportedProductTypes key, so upstream's
 * build_manifest_check_compatibility() always rejects it. Verify the silicon
 * identity instead - stricter, not weaker: a BuildIdentity must exist whose
 * ApChipID and ApBoardID equal this device's.
 * Returns 1 = match, 0 = no match, -1 = T1 mode off (use the normal check). */
int t1_manifest_matches_device(plist_t build_manifest, unsigned int chip_id, unsigned int board_id);

/* Called with the outgoing FDRTrustData reply dict and the incoming request.
 * Logs the request's shape (keys/types only) and, when armed, adds the
 * FDRTrustData key. */
void t1_augment_fdr_trust_data(plist_t reply, plist_t request);

/* --- phase 14 ------------------------------------------------------------- */

/* Replay a previously captured memboot image + AP ticket against a T1 sitting
 * in recovery (05ac:1281): auto-boot=false, send ticket, upload image, set
 * boot-args, then issue a blind `memboot` with USB bRequest=1.
 * Returns 0 if the transaction was dispatched. Dispatch success does NOT mean
 * the T1 accepted the image - the caller must observe USB state. */
int t1_phase14(struct idevicerestore_client_t *client);

#endif /* T1_H */
