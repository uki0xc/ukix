const productName = "Subscription";
const productType = "ai.suno.premier.annual";
const appVersion = null;
function headerValue(headers, name) {
    if (!headers) return null;
    const key = Object.keys(headers).find(item => item.toLowerCase() === name.toLowerCase());
    return key ? headers[key] : null;
}
function deleteHeader(headers, name) {
    if (!headers) return;
    const key = Object.keys(headers).find(item => item.toLowerCase() === name.toLowerCase());
    if (key) delete headers[key];
}
function rcDateFromRequestTime(headers) {
    const requestTime = headerValue(headers, "x-revenuecat-request-time");
    const timestamp = requestTime ? Number(requestTime) : Date.now();
    const date = Number.isFinite(timestamp) ? new Date(timestamp) : new Date();
    return date.toISOString().replace(/\.\d{3}Z$/, "Z");
}
// 新增：计算指定年数后的日期，并格式化为 RevenueCat 所需的 ISO 格式
function addYears(dateString, years) {
    const date = new Date(dateString);
    if (isNaN(date.getTime())) return dateString;
    date.setFullYear(date.getFullYear() + years);
    return date.toISOString().replace(/\.\d{3}Z$/, "Z");
}
if (typeof $response === "undefined") {
    const headers = $request.headers || {};
    deleteHeader(headers, "if-none-match");
    deleteHeader(headers, "x-revenuecat-etag");
    deleteHeader(headers, "x-rc-last-refresh-time");
    $done({ headers });
} else {
    const url = $request && $request.url ? $request.url : "";
    if (/\/offerings(?:[/?#]|$)/.test(url) || !$response.body) {
        $done({});
    } else {
        let obj;
        try {
            obj = JSON.parse($response.body);
        } catch {
            $done({});
        }
        const purchaseDate = rcDateFromRequestTime($response.headers);
        // 计算一年后的过期时间
        const expiresDate = addYears(purchaseDate, 1);
        const headers = $response.headers || {};
        deleteHeader(headers, "x-signature");
        deleteHeader(headers, "x-revenuecat-etag");
        obj.subscriber = {
            non_subscriptions: {},
            first_seen: purchaseDate,
            original_application_version: appVersion,
            other_purchases: {
                [productType]: {
                    price: { amount: 0, currency: "USD" },
                    display_name: null,
                    purchase_date: purchaseDate,
                    expires_date: expiresDate // 增加过期时间
                }
            },
            management_url: null,
            subscriptions: {},
            entitlements: {
                [productName]: {
                    grace_period_expires_date: null,
                    purchase_date: purchaseDate,
                    product_identifier: productType,
                    expires_date: expiresDate // 将 null 改为一年后的时间
                }
            },
            original_purchase_date: purchaseDate,
            original_app_user_id: "$RCAnonymousID:0400000000000000000000000000000",
            last_seen: purchaseDate
        };
        obj.subscriber.non_subscriptions[productType] = [{
            id: "aaaaaaaaaa",
            is_sandbox: false,
            price: { amount: 0, currency: "USD" },
            display_name: null,
            purchase_date: purchaseDate,
            original_purchase_date: purchaseDate,
            store: "app_store",
            store_transaction_id: "280000000000000"
        }];
        $done({ headers, body: JSON.stringify(obj) });
    }
}
