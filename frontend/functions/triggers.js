"use strict";

const { onDocumentWritten } = require("firebase-functions/v2/firestore");

const {
  db,
  clampString,
  deleteStorageUrl,
  queueNotification,
  writeAudit,
} = require("./helpers");
const {
  ensureChatForClaim,
  closeChatsForItem,
  closeChatForClaim,
} = require("./chat");

function itemSummary(data) {
  const title = clampString(data && data.title, 100);
  return title ? `"${title}"` : "(untitled item)";
}

function custodyKey(location) {
  return Buffer.from(clampString(location, 80), "utf8").toString("base64url").slice(0, 40);
}

/**
 * Authoritative audit trail, notifications and private-data cleanup for item
 * writes. Firestore does not cascade deletes to subcollections, so deleting an
 * item must also remove items/{id}/private/contact and the Storage photo.
 */
exports.onItemWritten = onDocumentWritten("items/{itemId}", async (event) => {
  const before = event.data.before;
  const after = event.data.after;
  const itemId = event.params.itemId;

  if (before.exists && !after.exists) {
    const data = before.data();
    await closeChatsForItem(itemId, "item deleted", data.updatedBy || "system").catch(() => {});
    await deleteStorageUrl(data.image).catch(() => {});
    await db.recursiveDelete(before.ref).catch(() => {});
    await writeAudit({
      actorUid: data.updatedBy || data.reporterUid || "system",
      actorRole: "system",
      action: "item.deleted",
      targetType: "item",
      targetId: itemId,
      details: `Deleted ${itemSummary(data)} and its private data/photo`,
    });
    return;
  }

  if (!after.exists) return;

  const data = after.data();
  if (!before.exists) {
    await writeAudit({
      actorUid: data.reporterUid || data.updatedBy || "system",
      actorRole: "system",
      action: "item.created",
      targetType: "item",
      targetId: itemId,
      details: `Created ${itemSummary(data)} (${data.type || "unknown"})`,
    });
    return;
  }

  const previous = before.data();
  // If a photo was replaced, remove the old Storage object so orphaned images
  // do not accumulate (and are not silently retained after moderation).
  if (previous.image && previous.image !== data.image) {
    await deleteStorageUrl(previous.image).catch(() => {});
  }

  const statusChanged = previous.status !== data.status;
  const details = statusChanged
    ? `${itemSummary(data)} status: ${previous.status || "?"} -> ${data.status || "?"}`
    : `Updated ${itemSummary(data)}`;

  await writeAudit({
    actorUid: data.updatedBy || data.reporterUid || "system",
    actorRole: "system",
    action: statusChanged ? "item.status_changed" : "item.updated",
    targetType: "item",
    targetId: itemId,
    details,
  });

  const reporterUid = data.reporterUid;
  const actorUid = data.updatedBy || "system";
  const title = clampString(data.title, 100) || "your report";

  if (statusChanged && reporterUid && reporterUid !== actorUid) {
    const messages = {
      approved: `Your report "${title}" was approved and is now visible on the campus board.`,
      rejected: `Your report "${title}" was rejected by campus staff.`,
      returned: `Your report "${title}" is marked returned. Thank you for helping.`,
    };
    if (messages[data.status]) {
      await queueNotification({
        toUid: reporterUid,
        text: messages[data.status],
        event: "claimStatus",
        url: "/index.html?view=dashboard",
        dedupeKey: `item_status_${itemId}_${previous.status || "none"}_${data.status}`,
      }).catch(() => {});
    }
  }

  if (statusChanged && data.status === "returned") {
    await closeChatsForItem(itemId, "item returned", actorUid).catch(() => {});
  }

  const custodyChanged =
    previous.custodyLocation !== data.custodyLocation ||
    previous.custodyHours !== data.custodyHours ||
    previous.isCustody !== data.isCustody;
  if (custodyChanged && reporterUid && reporterUid !== actorUid) {
    const location = clampString(data.custodyLocation, 120);
    await queueNotification({
      toUid: reporterUid,
      text: location
        ? `Custody details for "${title}" changed: ${location} ${clampString(data.custodyHours, 80)}`.trim()
        : `Custody details for "${title}" changed.`,
      event: "custodyUpdate",
      url: "/index.html?view=dashboard",
      dedupeKey: `item_custody_${itemId}_${custodyKey(location + "|" + clampString(data.custodyHours, 80))}`,
    }).catch(() => {});
  }
});

/**
 * Audit, private-proof cleanup, claim notifications, chat creation/closure and
 * handover readiness for claims. Students cannot write another member's
 * notification under the client rules, so this trigger is the safe path.
 */
exports.onClaimWritten = onDocumentWritten("claims/{claimId}", async (event) => {
  const before = event.data.before;
  const after = event.data.after;
  const claimId = event.params.claimId;

  if (before.exists && !after.exists) {
    const old = before.data();
    if (old.itemId && old.claimantUid) {
      await closeChatForClaim(old.itemId, old.claimantUid, "claim deleted", old.claimantUid).catch(
        () => {}
      );
    }
    await db.recursiveDelete(before.ref).catch(() => {});
    await writeAudit({
      actorUid: old.claimantUid || "system",
      actorRole: "system",
      action: "claim.deleted",
      targetType: "claim",
      targetId: claimId,
      details: `Deleted claim for ${old.itemTitle || "an item"} and its private proof`,
    });
    return;
  }

  if (!after.exists) return;
  const data = after.data();
  const itemTitle = clampString(data.itemTitle, 100) || "an item";

  if (!before.exists) {
    await writeAudit({
      actorUid: data.claimantUid || "system",
      actorRole: "system",
      action: "claim.created",
      targetType: "claim",
      targetId: claimId,
      details: `Claim submitted for ${itemTitle}`,
    });

    if (data.claimantUid) {
      await queueNotification({
        toUid: data.claimantUid,
        text: `We received your claim for "${itemTitle}". Campus staff will verify ownership.`,
        event: "claimReceived",
        url: "/index.html?view=dashboard",
        dedupeKey: `claim_received_claimant_${claimId}`,
      }).catch(() => {});
    }

    if (!data.itemId) return;
    try {
      const itemSnap = await db.collection("items").doc(data.itemId).get();
      if (!itemSnap.exists) return;
      const item = itemSnap.data();
      if (!item.reporterUid || item.reporterUid === data.claimantUid) return;
      await queueNotification({
        toUid: item.reporterUid,
        text: `A claim was submitted for your report "${itemTitle}". Faculty/Staff will verify ownership.`,
        event: "claimReceived",
        url: "/index.html?view=dashboard",
        dedupeKey: `claim_received_reporter_${claimId}`,
      });
    } catch (error) {
      // Notification delivery must never fail the claim itself.
    }
    return;
  }

  const previous = before.data();
  if (previous.status === data.status) return;

  await writeAudit({
    actorUid: data.reviewedBy || "system",
    actorRole: "system",
    action: `claim.${data.status || "updated"}`,
    targetType: "claim",
    targetId: claimId,
    details: `Claim for ${itemTitle} was ${data.status || "updated"}`,
  });

  if (data.status === "approved") {
    if (data.claimantUid) {
      await queueNotification({
        toUid: data.claimantUid,
        text: `Your claim for "${itemTitle}" was approved. A secure chat is now available to arrange pickup.`,
        event: "claimApproved",
        url: "/index.html?view=dashboard",
        dedupeKey: `claim_approved_claimant_${claimId}`,
      }).catch(() => {});
    }

    try {
      const created = await ensureChatForClaim(claimId, data);
      if (created && created.created && data.itemId) {
        const itemSnap = await db.collection("items").doc(data.itemId).get();
        const item = itemSnap.exists ? itemSnap.data() : null;
        if (item && item.reporterUid && item.reporterUid !== data.claimantUid) {
          await queueNotification({
            toUid: item.reporterUid,
            text: `Ownership of "${itemTitle}" was verified. A secure chat is now open with the claimant.`,
            event: "claimApproved",
            url: "/index.html?view=dashboard",
            dedupeKey: `claim_approved_reporter_${claimId}`,
          });
        }
        if (item && (item.custodyLocation || item.isCustody) && data.claimantUid) {
          await queueNotification({
            toUid: data.claimantUid,
            text: `"${itemTitle}" is ready for pickup. ${clampString(
              item.custodyLocation,
              120
            )} ${clampString(item.custodyHours, 80)}`.trim(),
            event: "readyForPickup",
            url: "/index.html?view=dashboard",
            dedupeKey: `claim_ready_${claimId}`,
          });
        }
      }
    } catch (error) {
      // The claim is still approved even if chat provisioning fails; the
      // claimant can retry via the ensureChat callable.
    }
    return;
  }

  if (data.status === "rejected") {
    if (data.claimantUid) {
      await queueNotification({
        toUid: data.claimantUid,
        text: `Your claim for "${itemTitle}" was not approved. Contact campus staff if you believe this is a mistake.`,
        event: "claimRejected",
        url: "/index.html?view=dashboard",
        dedupeKey: `claim_rejected_${claimId}`,
      }).catch(() => {});
    }
    if (data.itemId && data.claimantUid) {
      await closeChatForClaim(data.itemId, data.claimantUid, "claim rejected", data.reviewedBy).catch(
        () => {}
      );
    }
  }
});

/** Audit trail for informational user profile changes. */
exports.onUserWritten = onDocumentWritten("users/{uid}", async (event) => {
  const before = event.data.before;
  const after = event.data.after;
  const uid = event.params.uid;

  if (before.exists && !after.exists) {
    await writeAudit({
      actorUid: "system",
      actorRole: "system",
      action: "user.profile_deleted",
      targetType: "user",
      targetId: uid,
      details: "User profile document deleted",
    });
    return;
  }
  if (!after.exists) return;

  const data = after.data();
  if (!before.exists) {
    await writeAudit({
      actorUid: data.uid || uid,
      actorRole: "system",
      action: "user.profile_created",
      targetType: "user",
      targetId: uid,
      details: `Profile created for ${data.email || uid}`,
    });
    return;
  }

  const previous = before.data();
  const changed = [];
  ["name", "status", "role"].forEach((field) => {
    if (previous[field] !== data[field]) {
      changed.push(`${field}: ${previous[field] || "?"} -> ${data[field] || "?"}`);
    }
  });
  if (!changed.length) return;

  await writeAudit({
    actorUid: data.updatedBy || "system",
    actorRole: "system",
    action: "user.profile_updated",
    targetType: "user",
    targetId: uid,
    details: `${data.email || uid}: ${changed.join(", ")}`,
  });
});
