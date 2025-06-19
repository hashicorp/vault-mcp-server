let sessions = {};

export function getSession(sessionId) {
    if (!sessions[sessionId]) {
        return null;
    }
    return sessions[sessionId];
}

export function createSession(sessionId) {
    let session = {
        sessionId: sessionId,
        transport: null,
        vault: null,
    };

    sessions[sessionId] = session;
    return session;
}

export function deleteSession(sessionId) {
    if (sessions[sessionId]) {
        delete sessions[sessionId];
    }
}
