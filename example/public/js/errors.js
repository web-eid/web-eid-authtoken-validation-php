// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

"use strict";

const alertUi = {
    alert: document.querySelector("#error-message"),
    alertMessage: document.querySelector("#error-message .message"),
    alertDetails: document.querySelector("#error-message .details")
};

export function hideErrorMessage() {
    alertUi.alert.style.display = "none";
}

export function showErrorMessage(error) {
    const message = "Authentication failed";
    const details =
        `[Code]\n${error.code}` +
        `\n\n[Message]\n${error.message}` +
        (error.response ? `\n\n[response]\n${JSON.stringify(error.response, null, " ")}` : "");

    alertUi.alertMessage.innerText = message;
    alertUi.alertDetails.innerText = details;
    alertUi.alert.style.display = "block";
}

export async function checkHttpError(response) {
    if (!response.ok) {
        let body;
        try {
            body = await response.text();
        } catch (error) {
            body = "<<unable to retrieve response body>>";
        }
        const error = new Error("Server error: " + body);
        error.code = response.status;
        throw error;
    }
}