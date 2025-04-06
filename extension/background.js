chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === "complete" && tab.url) {
        chrome.storage.local.get("extensionEnabled", async (data) => {
            console.log("Phishing Guard is:", data.extensionEnabled ? "ON ✅" : "OFF ❌");
            if (!data.extensionEnabled) return; // ✅ No checks when OFF

            const apiUrl = `http://127.0.0.1:8000/predict?url=${encodeURIComponent(tab.url)}`;

            try {
                console.log("Checking URL:", tab.url);
                const response = await fetch(apiUrl);
                const result = await response.json();
                
                console.log("API Response:", result); // ✅ Debugging

                if (result.prediction === "Phishing") {
                    console.log("⚠️ PHISHING DETECTED! Injecting Warning...");
                    
                    chrome.scripting.executeScript({
                        target: { tabId: tabId },
                        func: () => {
                            alert("🚨 WARNING: This website may be a phishing site! Proceed with caution.");
                            if (!confirm("Do you want to continue?")) {
                                history.back();
                            }
                        }
                    });
                }
            } catch (error) {
                console.error("Error fetching phishing data:", error);
            }
        });
    }
});
