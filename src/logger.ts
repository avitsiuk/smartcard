type TNullableLogFunction = ((...args: any[]) => void) | null;

let customFatalLogFun: TNullableLogFunction = null;
let customErrorLogFun: TNullableLogFunction = null;
let customWarnLogFun: TNullableLogFunction = null;
let customInfoLogFun: TNullableLogFunction = null;
let customDebugLogFun: TNullableLogFunction = null;
let customTraceLogFun: TNullableLogFunction = null;

let currLogLevel: Logger.ELogLevel = Logger.ELogLevel.INFO;

function nullableLogFunctionCall(
    minLogLevel: Logger.ELogLevel,
    customLogFun: TNullableLogFunction,
    defLogFun: (...args: any[]) => void,
    ...args: any[]
): void {
    if (currLogLevel < minLogLevel) return;
    if(typeof customLogFun === 'function') {
        customLogFun(...args);
        return;
    }
    defLogFun(...args);
}

namespace Logger {

    /** Default fallback log functions */
    export namespace DefLogFun {
        export function fatal(...args: any[]): void {
            console.error(`[${Logger.utcDateStr()}][FATAL]: `, ...args);
        }
        export function error(...args: any[]): void {
            console.error(`[${Logger.utcDateStr()}][ERROR]: `, ...args);
        }
        export function warn(...args: any[]): void {
            console.warn(`[${Logger.utcDateStr()}][WARN]: `, ...args);
        }
        export function info(...args: any[]): void {
            console.info(`[${Logger.utcDateStr()}][INFO]: `, ...args);
        }
        export function debug(...args: any[]): void {
            console.log(`[${Logger.utcDateStr()}][DEBUG]: `, ...args);
        }
        export function trace(...args: any[]): void {
            console.log(`[${Logger.utcDateStr()}][TRACE]: `, ...args);
        }
    }

    /** 0 NONE; 1 FATAL; 2 ERROR; 3 WARN; 4 INFO; 5 DEBUG; 6 TRACE */
    export const enum ELogLevel {
        /** No logs will be produced */
        NONE,
        /** FATAL only */
        FATAL,
        /** ERROR, FATAL */
        ERROR,
        /** WARN, ERROR, FATAL */
        WARN,
        /** INFO, WARN, ERROR, FATAL */
        INFO,
        /** DEBUG, INFO, WARN, ERROR, FATAL */
        DEBUG,
        /** Everything */
        TRACE,
    };

    /** Example return: `2024-08-25T13:16:54.158Z` */
    export function utcDateStr(): string {
        return new Date().toISOString();
    }

    export function setLogLevel(logLvl: Logger.ELogLevel): typeof Logger {
        currLogLevel = logLvl;
        return Logger;
    }

    export function setFatalLogFun(logFun: TNullableLogFunction): typeof Logger {
        customFatalLogFun = logFun;
        return Logger;
    }
    export function setErrorLogFun(logFun: TNullableLogFunction): typeof Logger {
        customErrorLogFun = logFun;
        return Logger;
    }
    export function setWarnLogFun(logFun: TNullableLogFunction): typeof Logger {
        customWarnLogFun = logFun;
        return Logger;
    }
    export function setInfoLogFun(logFun: TNullableLogFunction): typeof Logger {
        customInfoLogFun = logFun;
        return Logger;
    }
    export function setDebugLogFun(logFun: TNullableLogFunction): typeof Logger {
        customDebugLogFun = logFun;
        return Logger;
    }
    export function setTraceLogFun(logFun: TNullableLogFunction): typeof Logger {
        customTraceLogFun = logFun;
        return Logger;
    }

    export function fatal(...args: any[]): void {
        nullableLogFunctionCall(Logger.ELogLevel.FATAL, customFatalLogFun, DefLogFun.fatal, ...args);
    }
    export function error(...args: any[]): void {
        nullableLogFunctionCall(Logger.ELogLevel.ERROR, customErrorLogFun, DefLogFun.error, ...args);
    }
    export function warn(...args: any[]): void {
        nullableLogFunctionCall(Logger.ELogLevel.WARN, customWarnLogFun, DefLogFun.warn, ...args);
    }
    export function info(...args: any[]): void {
        nullableLogFunctionCall(Logger.ELogLevel.INFO, customInfoLogFun, DefLogFun.info, ...args);
    }
    export function debug(...args: any[]): void {
        nullableLogFunctionCall(Logger.ELogLevel.DEBUG, customDebugLogFun, DefLogFun.debug, ...args);
    }
    export function trace(...args: any[]): void {
        nullableLogFunctionCall(Logger.ELogLevel.TRACE, customTraceLogFun, DefLogFun.trace, ...args);
    }

}

export default Logger
