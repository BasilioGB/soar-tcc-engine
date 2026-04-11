(function () {
    const SHOW_MESSAGE_EVENT = "showMessage";

    const incidentState = {
        socket: null,
        id: null,
        attempts: 0,
        manualClose: false,
    };

    const notifyState = {
        socket: null,
        attempts: 0,
        manualClose: false,
    };

    function buildSocketUrl(path) {
        const protocol = window.location.protocol === "https:" ? "wss" : "ws";
        const host = window.location.host;
        return `${protocol}://${host}${path}`;
    }

    function dispatchToast(level, text, clear = false) {
        document.body.dispatchEvent(
            new CustomEvent(SHOW_MESSAGE_EVENT, {
                detail: { level, text, clear },
            })
        );
    }

    function refreshIncidentSections(sectionNames) {
        if (!window.htmx) {
            return;
        }
        const available = Array.from(document.querySelectorAll("[data-incident-section]"));
        const sectionsMap = Object.create(null);
        available.forEach((element) => {
            sectionsMap[element.dataset.incidentSection] = element;
        });
        const names = sectionNames && sectionNames.length ? sectionNames : Object.keys(sectionsMap);
        names.forEach((name) => {
            const target = sectionsMap[name];
            if (!target) {
                return;
            }
            const url = target.dataset.refreshUrl;
            if (!url) {
                return;
            }
            window.htmx.ajax("GET", url, { target, swap: "outerHTML" });
        });
    }

    function handleIncidentMessage(message) {
        const sections = Array.isArray(message.sections) ? message.sections : [];
        refreshIncidentSections(sections);
        const payload = message.payload || {};
        if (payload.message) {
            dispatchToast("info", payload.message, false);
        }
    }

    function setupIncidentSocket(incidentId) {
        if (!incidentId) {
            return;
        }
        const url = buildSocketUrl(`/ws/incidents/${incidentId}/`);
        incidentState.manualClose = false;
        incidentState.socket = new WebSocket(url);

        incidentState.socket.onopen = function () {
            incidentState.attempts = 0;
        };

        incidentState.socket.onmessage = function (event) {
            try {
                const data = JSON.parse(event.data);
                if (data.type === "incident.update") {
                    handleIncidentMessage(data);
                }
            } catch (error) {
                console.warn("Falha ao processar mensagem de websocket", error);
            }
        };

        incidentState.socket.onclose = function (event) {
            incidentState.socket = null;
            if (incidentState.manualClose) {
                return;
            }
            if (event && [4000, 4001, 4003].includes(event.code)) {
                incidentState.manualClose = true;
                return;
            }
            const delay = Math.min(30000, 1000 * 2 ** incidentState.attempts);
            incidentState.attempts += 1;
            setTimeout(() => setupIncidentSocket(incidentId), delay);
        };

        incidentState.socket.onerror = function () {
            if (incidentState.socket) {
                incidentState.socket.close();
            }
        };
    }

    function ensureIncidentConnection() {
        const root = document.querySelector("[data-incident-page]");
        if (!root) {
            if (incidentState.socket) {
                incidentState.manualClose = true;
                incidentState.socket.close();
                incidentState.socket = null;
            }
            incidentState.id = null;
            return;
        }
        const incidentId = root.dataset.incidentId;
        if (!incidentId) {
            return;
        }
        if (incidentState.id === incidentId && incidentState.socket) {
            return;
        }
        if (incidentState.socket) {
            incidentState.manualClose = true;
            incidentState.socket.close();
            incidentState.socket = null;
        }
        incidentState.id = incidentId;
        incidentState.attempts = 0;
        setupIncidentSocket(incidentId);
    }

    function handleNotifyMessage(message) {
        const payload = message.payload || {};
        const text = payload.message || payload.title || "";
        if (text) {
            dispatchToast(payload.level || message.kind || "info", text, false);
        }
    }

    function setupNotifySocket() {
        const url = buildSocketUrl("/ws/notify/");
        notifyState.manualClose = false;
        notifyState.socket = new WebSocket(url);

        notifyState.socket.onopen = function () {
            notifyState.attempts = 0;
        };

        notifyState.socket.onmessage = function (event) {
            try {
                const data = JSON.parse(event.data);
                if (data.type === "notify") {
                    handleNotifyMessage(data);
                }
            } catch (error) {
                console.warn("Falha ao processar notificacao em tempo real", error);
            }
        };

        notifyState.socket.onclose = function (event) {
            notifyState.socket = null;
            if (notifyState.manualClose) {
                return;
            }
            if (event && event.code === 4001) {
                notifyState.manualClose = true;
                return;
            }
            const delay = Math.min(30000, 1000 * 2 ** notifyState.attempts);
            notifyState.attempts += 1;
            setTimeout(setupNotifySocket, delay);
        };

        notifyState.socket.onerror = function () {
            if (notifyState.socket) {
                notifyState.socket.close();
            }
        };
    }

    document.addEventListener("DOMContentLoaded", function () {
        ensureIncidentConnection();
        setupNotifySocket();
    });

    document.body.addEventListener("htmx:afterSwap", ensureIncidentConnection);
})(); 
