use crate::detect::Detection;

pub fn detect(input: &str) -> Option<Detection> {
    let input = input.trim();

    // Must be exactly a 3-digit number
    if input.len() != 3 || !input.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }

    let code: u16 = input.parse().ok()?;
    if code < 100 || code > 599 {
        return None;
    }

    let (name, description) = status_info(code)?;

    let category = match code {
        100..=199 => "Informational",
        200..=299 => "Success",
        300..=399 => "Redirection",
        400..=499 => "Client Error",
        500..=599 => "Server Error",
        _ => unreachable!(),
    };

    let mut fields = Vec::new();
    fields.push(("Code".into(), code.to_string()));
    fields.push(("Name".into(), name.to_string()));
    fields.push(("Category".into(), category.to_string()));
    fields.push(("Description".into(), description.to_string()));

    Some(Detection {
        label: "HTTP Status Code".into(),
        confidence: 0.85,
        fields,
    })
}

fn status_info(code: u16) -> Option<(&'static str, &'static str)> {
    let info = match code {
        // 1xx Informational
        100 => ("Continue", "Server received request headers, client should proceed to send body"),
        101 => ("Switching Protocols", "Server is switching protocols as requested by client"),
        102 => ("Processing", "Server has received and is processing the request (WebDAV)"),
        103 => ("Early Hints", "Server sends preliminary response headers before final response"),

        // 2xx Success
        200 => ("OK", "Request succeeded"),
        201 => ("Created", "Request succeeded and a new resource was created"),
        202 => ("Accepted", "Request accepted for processing but not yet completed"),
        203 => ("Non-Authoritative Information", "Response metadata is from a local or third-party copy"),
        204 => ("No Content", "Request succeeded but there is no content to send"),
        205 => ("Reset Content", "Server asks client to reset the document view"),
        206 => ("Partial Content", "Server is delivering only part of the resource due to range header"),
        207 => ("Multi-Status", "Response provides status for multiple independent operations (WebDAV)"),
        208 => ("Already Reported", "Members of a DAV binding have already been enumerated (WebDAV)"),
        226 => ("IM Used", "Server has fulfilled a GET request with instance-manipulations applied"),

        // 3xx Redirection
        300 => ("Multiple Choices", "Request has multiple possible responses, client should choose one"),
        301 => ("Moved Permanently", "Resource has been permanently moved to a new URL"),
        302 => ("Found", "Resource temporarily resides under a different URL"),
        303 => ("See Other", "Response can be found at a different URL using GET"),
        304 => ("Not Modified", "Resource has not been modified since last request"),
        305 => ("Use Proxy", "Resource must be accessed through specified proxy (deprecated)"),
        307 => ("Temporary Redirect", "Resource temporarily at another URL, same method must be used"),
        308 => ("Permanent Redirect", "Resource permanently at another URL, same method must be used"),

        // 4xx Client Error
        400 => ("Bad Request", "Server cannot process request due to malformed syntax"),
        401 => ("Unauthorized", "Authentication is required and has not been provided"),
        402 => ("Payment Required", "Reserved for future use, sometimes used for payment-required APIs"),
        403 => ("Forbidden", "Server understood the request but refuses to authorize it"),
        404 => ("Not Found", "Requested resource could not be found on the server"),
        405 => ("Method Not Allowed", "HTTP method is not supported for the requested resource"),
        406 => ("Not Acceptable", "No content matching the Accept headers was found"),
        407 => ("Proxy Authentication Required", "Client must authenticate with the proxy first"),
        408 => ("Request Timeout", "Server timed out waiting for the client request"),
        409 => ("Conflict", "Request conflicts with the current state of the server"),
        410 => ("Gone", "Resource has been permanently deleted and is no longer available"),
        411 => ("Length Required", "Server requires a Content-Length header in the request"),
        412 => ("Precondition Failed", "One or more conditions in the request headers evaluated to false"),
        413 => ("Payload Too Large", "Request entity is larger than the server is willing to process"),
        414 => ("URI Too Long", "Request URI is longer than the server is willing to interpret"),
        415 => ("Unsupported Media Type", "Request payload format is not supported by the server"),
        416 => ("Range Not Satisfiable", "Requested range cannot be fulfilled by the server"),
        417 => ("Expectation Failed", "Server cannot meet the requirements of the Expect header"),
        418 => ("I'm a Teapot", "Server refuses to brew coffee because it is a teapot (RFC 2324)"),
        421 => ("Misdirected Request", "Request was directed at a server unable to produce a response"),
        422 => ("Unprocessable Entity", "Request was well-formed but contains semantic errors (WebDAV)"),
        423 => ("Locked", "Resource being accessed is locked (WebDAV)"),
        424 => ("Failed Dependency", "Request failed because a previous request failed (WebDAV)"),
        425 => ("Too Early", "Server is unwilling to process a request that might be replayed"),
        426 => ("Upgrade Required", "Server requires the client to switch to a different protocol"),
        428 => ("Precondition Required", "Server requires the request to be conditional"),
        429 => ("Too Many Requests", "Client has sent too many requests in a given time period"),
        431 => ("Request Header Fields Too Large", "Server refuses request because headers are too large"),
        451 => ("Unavailable For Legal Reasons", "Resource is unavailable due to legal demands"),

        // 5xx Server Error
        500 => ("Internal Server Error", "Server encountered an unexpected condition"),
        501 => ("Not Implemented", "Server does not support the requested functionality"),
        502 => ("Bad Gateway", "Server received an invalid response from an upstream server"),
        503 => ("Service Unavailable", "Server is temporarily unable to handle the request"),
        504 => ("Gateway Timeout", "Server did not receive a timely response from upstream server"),
        505 => ("HTTP Version Not Supported", "Server does not support the HTTP version used in request"),
        506 => ("Variant Also Negotiates", "Server has a configuration error in content negotiation"),
        507 => ("Insufficient Storage", "Server cannot store the representation needed (WebDAV)"),
        508 => ("Loop Detected", "Server detected an infinite loop while processing request (WebDAV)"),
        510 => ("Not Extended", "Further extensions to the request are required by the server"),
        511 => ("Network Authentication Required", "Client needs to authenticate to gain network access"),

        _ => return None,
    };
    Some(info)
}
