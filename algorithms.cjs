const SUPPORTED_ALGOS = [
    "cwm_minotaurx",
    "cwm_yespower",
    "cwm_yespowerR16",
    "cwm_yespowerR32",
    "cwm_yespowerTIDE",
    "cwm_yespowerADVC",
    "cwm_ghostrider",
    "cwm_power2B",
    "cwm_qubit",
    "cwm_rinhash",
    "cwm_verushash",
    "cwm_yescrypt",
    "cwm_yescryptR8",
    "cwm_yescryptR16",
    "cwm_yescryptR32"
];

const ALGO_LABELS = {
    cwm_minotaurx: "Minotaurx (KEY, PLSR, AVN, ...)",
    cwm_yespower: "YesPower (VISH, SMT, YTN, ...)",
    cwm_yespowerR16: "YesPowerR16 (YTN, ...)",
    cwm_yespowerR32: "YesPowerR32",
    cwm_yespowerTIDE: "YesPowerTIDE (TIDE, ...)",
    cwm_yespowerADVC: "YesPowerADVC (ADVC, ...)",
    cwm_ghostrider: "Ghostrider (RTM, ...)",
    cwm_power2B: "Power2B (MicroBitcoin, ...)",
    cwm_qubit: "Qubit",
    cwm_rinhash: "RinHash",
    cwm_verushash: "VerusHash (VRSC, ...)",
    cwm_yescrypt: "Yescrypt (BSTY, XMY, UIS, ...)",
    cwm_yescryptR8: "YescryptR8 (MBTC, ...)",
    cwm_yescryptR16: "YescryptR16 (GOLD, FENEC, ...)",
    cwm_yescryptR32: "YescryptR32 (UNFY, DMS, ...)"
};

const ALGO_ALIASES = {
    power2b: "cwm_power2B",
    cwm_power2b: "cwm_power2B",
    qubit: "cwm_qubit",
    rinhash: "cwm_rinhash",
    rin: "cwm_rinhash",
    yespower: "cwm_yespower",
    cpupower: "cwm_yespower",
    verus: "cwm_verushash",
    verushash: "cwm_verushash"
};

const SUPPORTED_SET = new Set(SUPPORTED_ALGOS);

function normalizeAlgo(input, options = {}) {
    const strict = options.strict === true;
    const raw = String(input || "").trim();
    if (!raw) return SUPPORTED_ALGOS[0];
    if (SUPPORTED_SET.has(raw)) return raw;

    const lowered = raw.toLowerCase();
    if (ALGO_ALIASES[lowered] && SUPPORTED_SET.has(ALGO_ALIASES[lowered])) {
        return ALGO_ALIASES[lowered];
    }
    if (strict) {
        throw new Error(`Unsupported algo: ${raw}`);
    }
    return SUPPORTED_ALGOS[0];
}

module.exports = {
    SUPPORTED_ALGOS,
    ALGO_LABELS,
    normalizeAlgo
};