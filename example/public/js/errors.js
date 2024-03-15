/*
 * Copyright (c) 2020-2024 Estonian Information System Authority
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

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