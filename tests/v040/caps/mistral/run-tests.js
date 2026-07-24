"use strict";

const checkModule = require("../../../../checks/v040-caps.js");
const { run, verifyCapabilities, subsetOk } = checkModule;

let pass = 0;
let fail = 0;

function test(name, fn) {
    try {
        const result = fn();
        if (result) {
            console.log("PASS " + name);
            pass++;
        } else {
            console.log("FAIL " + name + " " + (result === false ? "unexpected result" : String(result)));
            fail++;
        }
    } catch (e) {
        console.log("FAIL " + name + " exception: " + String(e));
        fail++;
    }
}

function makeBaseCtx() {
    return {
        grant: {
            schema_version: "1.0",
            skill_id: "test-skill",
            grants: {
                filesystem: {
                    read: ["/inputs"],
                    write: ["/outputs"]
                },
                model: {
                    allowed: ["gpt-3.5-turbo"]
                },
                subprocess: {
                    allowed: ["python3"]
                },
                network: {
                    destinations: ["api.example.com"]
                }
            },
            enforced: ["filesystem", "model"]
        },
        requested: {
            filesystem: {
                read: ["/inputs/file.txt"],
                write: ["/outputs/result.txt"]
            },
            model: {
                allowed: ["gpt-3.5-turbo"]
            }
        },
        attested: {
            filesystem: true,
            model: true
        }
    };
}

// D1 FAIL-OPEN tests
test("D1-fail-open-filesystem-not-enforced", () => {
    const ctx = makeBaseCtx();
    ctx.grant.enforced = ["model"];
    ctx.attested.filesystem = true;
    const result = run(ctx);
    return result.status === "failed" && result.reason.includes("NOT in the enforced set");
});

test("D1-fail-open-model-not-enforced", () => {
    const ctx = makeBaseCtx();
    ctx.grant.enforced = ["filesystem"];
    ctx.attested.model = true;
    const result = run(ctx);
    return result.status === "failed" && result.reason.includes("NOT in the enforced set");
});

test("D1-fail-open-subprocess-not-enforced", () => {
    const ctx = makeBaseCtx();
    ctx.attested.subprocess = true;
    const result = run(ctx);
    return result.status === "failed" && result.reason.includes("NOT in the enforced set");
});

test("D1-fail-open-network-not-enforced", () => {
    const ctx = makeBaseCtx();
    ctx.attested.network = true;
    const result = run(ctx);
    return result.status === "failed" && result.reason.includes("NOT in the enforced set");
});

// ESCALATION tests
test("escalation-filesystem-read-outside-grant", () => {
    const ctx = makeBaseCtx();
    ctx.requested.filesystem.read = ["/etc/passwd"];
    const result = run(ctx);
    return result.status === "failed" && result.reason.includes("requested ⊄ granted");
});

test("escalation-filesystem-write-outside-grant", () => {
    const ctx = makeBaseCtx();
    ctx.requested.filesystem.write = ["/etc/passwd"];
    const result = run(ctx);
    return result.status === "failed" && result.reason.includes("requested ⊄ granted");
});

test("escalation-model-outside-allowlist", () => {
    const ctx = makeBaseCtx();
    ctx.requested.model.allowed = ["gpt-4"];
    const result = run(ctx);
    return result.status === "failed" && result.reason.includes("requested ⊄ granted");
});

test("escalation-subprocess-outside-allowlist", () => {
    const ctx = makeBaseCtx();
    ctx.requested.subprocess = { allowed: ["bash"] };
    ctx.attested.subprocess = true;
    const result = run(ctx);
    return result.status === "failed" && result.reason.includes("requested ⊄ granted");
});

test("escalation-network-outside-allowlist", () => {
    const ctx = makeBaseCtx();
    ctx.requested.network = { destinations: ["evil.com"] };
    ctx.attested.network = true;
    const result = run(ctx);
    return result.status === "failed" && result.reason.includes("requested ⊄ granted");
});

// PATH-PREFIX CONFUSION tests
test("path-prefix-confusion-simple-bypass", () => {
    const ctx = makeBaseCtx();
    ctx.grant.grants.filesystem.read = ["/inputs"];
    ctx.requested.filesystem.read = ["/inputs-evil/secret"];
    const result = run(ctx);
    return result.status === "failed";
});

test("path-prefix-confusion-traversal-bypass", () => {
    const ctx = makeBaseCtx();
    ctx.grant.grants.filesystem.read = ["/inputs"];
    ctx.requested.filesystem.read = ["/inputs/../etc/passwd"];
    const result = run(ctx);
    return result.status === "failed";
});

test("path-prefix-confusion-no-trailing-slash", () => {
    const ctx = makeBaseCtx();
    ctx.grant.grants.filesystem.read = ["/inputs"];
    ctx.requested.filesystem.read = ["/inputsevil"];
    const result = run(ctx);
    return result.status === "failed";
});

test("path-prefix-confusion-case-sensitivity", () => {
    const ctx = makeBaseCtx();
    ctx.grant.grants.filesystem.read = ["/Inputs"];
    ctx.requested.filesystem.read = ["/inputs/file.txt"];
    const result = run(ctx);
    return result.status === "failed";
});

// ALLOWLIST BYPASS tests
test("allowlist-bypass-model-case", () => {
    const ctx = makeBaseCtx();
    ctx.requested.model.allowed = ["GPT-3.5-TURBO"];
    const result = run(ctx);
    return result.status === "failed";
});

test("allowlist-bypass-model-whitespace", () => {
    const ctx = makeBaseCtx();
    ctx.requested.model.allowed = ["gpt-3.5-turbo "];
    const result = run(ctx);
    return result.status === "failed";
});

test("allowlist-bypass-model-duplicate", () => {
    const ctx = makeBaseCtx();
    ctx.requested.model.allowed = ["gpt-3.5-turbo", "gpt-3.5-turbo"];
    const result = run(ctx);
    return result.status === "verified"; // duplicates should be fine
});

test("allowlist-bypass-subprocess-case", () => {
    const ctx = makeBaseCtx();
    ctx.grant.grants.subprocess = { allowed: ["python3"] };
    ctx.requested.subprocess = { allowed: ["Python3"] };
    ctx.attested.subprocess = true;
    const result = run(ctx);
    return result.status === "failed";
});

test("allowlist-bypass-network-case", () => {
    const ctx = makeBaseCtx();
    ctx.grant.grants.network = { destinations: ["api.example.com"] };
    ctx.requested.network = { destinations: ["API.EXAMPLE.COM"] };
    ctx.attested.network = true;
    const result = run(ctx);
    return result.status === "failed";
});

// C1 tests
test("C1-skill-id-change", () => {
    const ctx1 = makeBaseCtx();
    const ctx2 = makeBaseCtx();
    ctx2.grant.skill_id = "different-skill";
    const result1 = run(ctx1);
    const result2 = run(ctx2);
    return result1.status === result2.status;
});

// Malformed input tests
test("malformed-null-ctx", () => {
    const result = run(null);
    return result.status === "failed";
});

test("malformed-wrong-type-ctx", () => {
    const result = run("not an object");
    return result.status === "failed";
});

test("malformed-missing-grant", () => {
    const ctx = makeBaseCtx();
    delete ctx.grant;
    const result = run(ctx);
    return result.status === "failed";
});

test("malformed-wrong-schema-version", () => {
    const ctx = makeBaseCtx();
    ctx.grant.schema_version = "2.0";
    const result = run(ctx);
    return result.status === "failed";
});

test("malformed-null-grants", () => {
    const ctx = makeBaseCtx();
    ctx.grant.grants = null;
    const result = run(ctx);
    return result.status === "failed" || result.status === "unavailable";
});

test("malformed-hostile-getters", () => {
    const ctx = makeBaseCtx();
    Object.defineProperty(ctx, 'grant', {
        get() { throw new Error("evil getter"); }
    });
    const result = run(ctx);
    return result.status === "failed";
});

test("malformed-proto-pollution", () => {
    const ctx = makeBaseCtx();
    ctx.__proto__.evil = true;
    const result = run(ctx);
    return result.status !== "failed" || !result.reason.includes("evil");
});

test("malformed-proxy", () => {
    const ctx = makeBaseCtx();
    const proxy = new Proxy(ctx, {
        get(target, prop) {
            if (prop === 'grant') throw new Error("proxy attack");
            return target[prop];
        }
    });
    const result = run(proxy);
    return result.status === "failed";
});

test("malformed-bigint", () => {
    const ctx = makeBaseCtx();
    ctx.grant.skill_id = 123n;
    const result = run(ctx);
    return result.status === "failed";
});

test("malformed-wrong-types-in-requested", () => {
    const ctx = makeBaseCtx();
    ctx.requested.filesystem.read = "not an array";
    const result = run(ctx);
    return result.status === "failed" || result.status === "verified";
});

test("malformed-wrong-types-in-attested", () => {
    const ctx = makeBaseCtx();
    ctx.attested.filesystem = "not a boolean";
    const result = run(ctx);
    return result.status === "failed";
});

console.log("# summary PASS=" + pass + " FAIL=" + fail + " total=" + (pass + fail));
process.exitCode = fail === 0 ? 0 : 1;
