package apns

import (
	"maps"
	"slices"
)

// knownReasons is the closed set of Apple reasons the relay reports or logs; anything else becomes "other".
var knownReasons = map[string]bool{
	"BadCollapseId": true, "BadDeviceToken": true, "BadExpirationDate": true, "BadMessageId": true,
	"BadPriority": true, "BadTopic": true, "DeviceTokenNotForTopic": true, "DuplicateHeaders": true,
	"IdleTimeout": true, "InvalidPushType": true, "MissingDeviceToken": true, "MissingTopic": true,
	"PayloadEmpty": true, "TopicDisallowed": true, "BadCertificate": true, "BadCertificateEnvironment": true,
	"ExpiredProviderToken": true, "Forbidden": true, "InvalidProviderToken": true, "MissingProviderToken": true,
	"UnrelatedKeyIdInToken": true, "BadEnvironmentKeyInToken": true, "BadPath": true, "MethodNotAllowed": true,
	"ExpiredToken": true, "Unregistered": true, "PayloadTooLarge": true, "TooManyProviderTokenUpdates": true,
	"TooManyRequests": true, "InternalServerError": true, "ServiceUnavailable": true, "Shutdown": true,
}

// ReasonLabel returns reason when it is one of Apple's known reasons and "other" for anything else, the
// empty reason included, so a metric label stays inside a closed set whatever Apple sends.
func ReasonLabel(reason string) string {
	if knownReasons[reason] {
		return reason
	}
	return "other"
}

// ReasonLabels returns every value ReasonLabel can return, sorted.
func ReasonLabels() []string {
	return append(slices.Sorted(maps.Keys(knownReasons)), "other")
}
