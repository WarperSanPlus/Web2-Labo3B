let timeOutPage = "";

class PartialRefresh {
    constructor(serviceURL, container, refreshRate, postRefreshCallback = null) {
        this.serviceURL = serviceURL;
        this.container = container;
        this.postRefreshCallback = postRefreshCallback;
        this.refreshRate = refreshRate * 1000;
        this.paused = false;
        this.refresh(true);
        setInterval(() => { this.refresh() }, this.refreshRate);
    }
    static setTimeOutPage(page) {
        timeOutPage = page;
    }
    pause() { this.paused = true }

    restart() { this.paused = false }

    replaceContent(htmlContent) {
        if (htmlContent !== "") {
            $("#" + this.container).html(htmlContent);
            if (this.postRefreshCallback != null) this.postRefreshCallback();
        }
    }

    static redirectToTimeOutPage() {
        console.log(this.timeOutPage)
        window.location = this.timeOutPage;
    }

    refresh(forced = false) {
        if (!this.paused) {
            $.ajax({
                url: this.serviceURL + (forced ? (this.serviceURL.indexOf("?") > -1 ? "&" : "?") + "forceRefresh=true" : ""),
                dataType: "html",
                success: (htmlContent) => { this.replaceContent(htmlContent) },
                statusCode: {
                    408: function () {
                        if (timeOutPage != "")
                            window.location = timeOutPage;
                        else
                            alert("Time out occured!");
                    }
                }
            })
        }
    }

    command(url) {
        $.ajax({
            url: url,
            method: 'GET',
            success: () => { this.refresh(true) }
        });
    }

    confirmedCommand(message, url) {
        bootbox.confirm(message, (result) => { if (result) this.command(url) });
    }
}
