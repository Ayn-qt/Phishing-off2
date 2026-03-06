document.addEventListener("DOMContentLoaded", () => {

const result = document.getElementById("result");
const urlText = document.getElementById("url");
const riskText = document.getElementById("risk");
const detailsBox = document.getElementById("details");

const scanCurrent = document.getElementById("check");
const scanInput = document.getElementById("scanInput");
const inputField = document.getElementById("urlInput");

async function checkURL(url){

    try{

        const response = await fetch("http://127.0.0.1:5000/predict",{
            method:"POST",
            headers:{
                "Content-Type":"application/json"
            },
            body:JSON.stringify({url})
        });

        const data = await response.json();

        /* STATUS */

        result.textContent = data.status;
        result.className = data.status === "PHISHING" ? "phishing" : "safe";

        /* RISK SCORE */

        riskText.textContent = data.risk_score + "%";
        if(data.risk_score < 30){
            riskText.style.color = "#4CAF50";
        }
        else if(data.risk_score < 60){
            riskText.style.color = "#ffc107";
        }
        else{
            riskText.style.color = "#ff5252";
        }

          

        /* DETAILS REPORT */

        let detailsHTML = "";

        detailsHTML += `
        <div class="detail-row">
            <span>HTTPS</span>
            <span class="${data.details.ssl ? 'good' : 'bad'}">
                ${data.details.ssl ? 'Detected' : 'Not detected'}
            </span>
        </div>`;

        detailsHTML += `
        <div class="detail-row">
            <span>IP Address in URL</span>
            <span class="${data.details.ip_address ? 'bad' : 'good'}">
                ${data.details.ip_address ? 'Present' : 'Not present'}
            </span>
        </div>`;

        detailsHTML += `
        <div class="detail-row">
            <span>Suspicious Keywords</span>
            <span class="${data.details.keywords ? 'bad' : 'good'}">
                ${data.details.keywords ? 'Detected' : 'None'}
            </span>
        </div>`;

        detailsBox.innerHTML = detailsHTML;

    }catch(error){

        result.textContent = "API ERROR";
        result.className = "";
        riskText.textContent = "--";
        detailsBox.innerHTML = "";

    }

}

/* scan current website */

scanCurrent.addEventListener("click", async ()=>{

    let tabs = await chrome.tabs.query({
        active:true,
        currentWindow:true
    });

    let url = tabs[0].url;

    let domain = new URL(url).hostname;
    urlText.textContent = domain;

    checkURL(url);

});

/* scan pasted link */

scanInput.addEventListener("click", ()=>{

    let url = inputField.value.trim();

    if(url === ""){
        result.textContent = "Enter a URL first";
        result.className = "";
        return;
    }

    urlText.textContent = new URL(url).hostname;

    checkURL(url);

});

});