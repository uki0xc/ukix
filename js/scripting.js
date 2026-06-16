const targetBundleId = "dev.fuxiao.app.Hamster";

function getHeader(headers, name) {
    if (!headers) return null;
    const key = Object.keys(headers).find(item => item.toLowerCase() === name.toLowerCase());
    return key ? headers[key] : null;
}

function mask(value) {
    if (!value || value.length <= 12) return value || "";
    return `${value.slice(0, 8)}...${value.slice(-4)}`;
}

function pathFromUrl(url) {
    return (url || "").replace(/^https?:\/\/[^/]+/i, "");
}

function rcDate(headers) {
    const raw = getHeader(headers, "x-revenuecat-request-time");
    const timestamp = raw ? Number(raw) : NaN;
    return Number.isFinite(timestamp) ? new Date(timestamp).toISOString() : null;
}

function objectKeys(value) {
    return value && typeof value === "object" ? Object.keys(value) : [];
}

function log(message, data) {
    const suffix = data ? ` ${JSON.stringify(data)}` : "";
    console.log(`[Scripting RevenueCat] ${message}${suffix}`);
}

const requestHeaders = ($request && $request.headers) || {};
const bundleId = getHeader(requestHeaders, "x-client-bundle-id");

if (bundleId !== targetBundleId) {
    $done({});
} else if (typeof $response === "undefined") {
    log("request", {
        bundleId,
        method: $request.method,
        path: pathFromUrl($request.url),
        authorization: mask(getHeader(requestHeaders, "authorization")),
        etag: getHeader(requestHeaders, "x-revenuecat-etag"),
        lastRefreshTime: getHeader(requestHeaders, "x-rc-last-refresh-time"),
        revenueCatSdk: getHeader(requestHeaders, "x-version"),
        appVersion: getHeader(requestHeaders, "x-client-version"),
        buildVersion: getHeader(requestHeaders, "x-client-build-version")
    });

    $done({});
} else {
    const responseHeaders = $response.headers || {};
    const body = $response.body || "";
    const result = {
        bundleId,
        status: $response.status,
        path: pathFromUrl($request.url),
        requestTime: getHeader(responseHeaders, "x-revenuecat-request-time"),
        requestTimeISO: rcDate(responseHeaders),
        responseEtag: getHeader(responseHeaders, "x-revenuecat-etag"),
        hasBody: body.length > 0
    };

    if (body) {
        try {
            const obj = JSON.parse(body);
            result.topLevelKeys = objectKeys(obj);

            if (obj.subscriber) {
                result.subscriberKeys = objectKeys(obj.subscriber);
                result.entitlementNames = objectKeys(obj.subscriber.entitlements);
                result.subscriptionProducts = objectKeys(obj.subscriber.subscriptions);
                result.nonSubscriptionProducts = objectKeys(obj.subscriber.non_subscriptions);
            }

            if (obj.offerings) {
                result.offeringKeys = objectKeys(obj.offerings);
                result.currentOfferingId = obj.current_offering_id || null;
            }
        } catch (error) {
            result.parseError = String(error && error.message ? error.message : error);
        }
    }

    log("response", result);
    $done({});
}
