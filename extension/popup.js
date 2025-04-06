document.addEventListener("DOMContentLoaded", () => {
    const toggleSwitch = document.getElementById("toggleExtension");
    const scanBtn = document.getElementById("scanBtn");

    // Load stored toggle state & update UI
    chrome.storage.local.get("extensionEnabled", (data) => {
        console.log("Loaded extension state:", data);
        toggleSwitch.checked = data.extensionEnabled !== undefined ? data.extensionEnabled : true;
    });

    // Toggle ON/OFF
    toggleSwitch.addEventListener("change", () => {
        const isEnabled = toggleSwitch.checked;
        chrome.storage.local.set({ extensionEnabled: isEnabled }, () => {
            console.log(`Phishing Guard ${isEnabled ? "ENABLED ✅" : "DISABLED ❌"}`);
        });
    });

    // Scan button functionality
    scanBtn.addEventListener("click", async () => {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        const apiUrl = `http://127.0.0.1:8000/predict?url=${encodeURIComponent(tab.url)}`;

        try {
            const response = await fetch(apiUrl);
            const data = await response.json();
            console.log(data)
            const resultElem = document.getElementById("result");

            if (data.prediction === "Phishing") {
                resultElem.innerHTML = `🚨 <span class="phishing">WARNING: PHISHING SITE DETECTED!</span> <p class="phishing">${data.probability}%</p> `;
            } else {
                resultElem.innerHTML = `✅ <span class="safe">This site is SAFE.</span> <p class="safe">${data.probability}%</p>`;
            }
        } catch (error) {
            console.error("Error checking site:", error);
            document.getElementById("result").innerText = "⚠️ Error fetching data.";
        }
    });
});
