/**
 * @method shifty.tween
 * @param {shifty.tweenConfig} [config={}]
 * @description Standalone convenience method that functions identically to
 * {@link Tweenable#tween}.  You can use this to create tweens without
 * needing to set up a {@link Tweenable} instance.
 *
 * ```
 * import { tween } from 'shifty';
 *
 * tween({ from: { x: 0 }, to: { x: 10 } }).then(
 *   () => console.log('All done!')
 * );
 * ```
 *
 * @returns {Tweenable} A new {@link Tweenable} instance.
 */
export function tween(config?: shifty.tweenConfig): Tweenable;
export function resetList(): void;
export function getListHead(): Tweenable;
export function getListTail(): Tweenable;
export function tweenProps(forPosition: number, currentState: any, originalState: any, targetState: any, duration: number, timestamp: number, easing: Record<string, string | Function>): any;
export function processTweens(): void;
export function shouldScheduleUpdate(doScheduleUpdate: boolean): void;
export function scheduleUpdate(): void;
export function composeEasingObject(fromTweenParams: Record<string, string | Function>, easing?: any | string | Function | Array<number>, composedEasing?: any): Record<string, string | Function> | Function;
/**
 * @class
 * @implements {Promise<unknown>}
 */
export class Tweenable implements Promise<unknown> {
    /**
     * @method Tweenable.now
     * @static
     * @returns {number} The current timestamp.
     */
    static now: () => number;
    /**
     * Set a custom schedule function.
     *
     * By default,
     * [`requestAnimationFrame`](https://developer.mozilla.org/en-US/docs/Web/API/window.requestAnimationFrame)
     * is used if available, otherwise
     * [`setTimeout`](https://developer.mozilla.org/en-US/docs/Web/API/Window.setTimeout)
     * is used.
     * @method Tweenable.setScheduleFunction
     * @param {shifty.scheduleFunction} fn The function to be
     * used to schedule the next frame to be rendered.
     * @return {shifty.scheduleFunction} The function that was set.
     */
    static setScheduleFunction: (fn: shifty.scheduleFunction) => shifty.scheduleFunction;
    /**
     * The {@link shifty.filter}s available for use.  These filters are
     * automatically applied at tween-time by Shifty. You can define your own
     * {@link shifty.filter}s and attach them to this object.
     * @member Tweenable.filters
     * @type {Record<string, shifty.filter>}
     */
    static filters: Record<string, shifty.filter>;
    static formulas: {
        linear: import("./index").shifty.easingFunction;
        easeInQuad: import("./index").shifty.easingFunction;
        easeOutQuad: import("./index").shifty.easingFunction;
        easeInOutQuad: import("./index").shifty.easingFunction;
        easeInCubic: import("./index").shifty.easingFunction;
        easeOutCubic: import("./index").shifty.easingFunction;
        easeInOutCubic: import("./index").shifty.easingFunction;
        easeInQuart: import("./index").shifty.easingFunction;
        easeOutQuart: import("./index").shifty.easingFunction;
        easeInOutQuart: import("./index").shifty.easingFunction;
        easeInQuint: import("./index").shifty.easingFunction;
        easeOutQuint: import("./index").shifty.easingFunction;
        easeInOutQuint: import("./index").shifty.easingFunction;
        easeInSine: import("./index").shifty.easingFunction;
        easeOutSine: import("./index").shifty.easingFunction;
        easeInOutSine: import("./index").shifty.easingFunction;
        easeInExpo: import("./index").shifty.easingFunction;
        easeOutExpo: import("./index").shifty.easingFunction;
        easeInOutExpo: import("./index").shifty.easingFunction;
        easeInCirc: import("./index").shifty.easingFunction;
        easeOutCirc: import("./index").shifty.easingFunction;
        easeInOutCirc: import("./index").shifty.easingFunction;
        easeOutBounce: import("./index").shifty.easingFunction;
        easeInBack: import("./index").shifty.easingFunction;
        easeOutBack: import("./index").shifty.easingFunction;
        easeInOutBack: import("./index").shifty.easingFunction;
        elastic: import("./index").shifty.easingFunction;
        swingFromTo: import("./index").shifty.easingFunction;
        swingFrom: import("./index").shifty.easingFunction;
        swingTo: import("./index").shifty.easingFunction;
        bounce: import("./index").shifty.easingFunction;
        bouncePast: import("./index").shifty.easingFunction;
        easeFromTo: import("./index").shifty.easingFunction;
        easeFrom: import("./index").shifty.easingFunction;
        easeTo: import("./index").shifty.easingFunction;
    };
    /**
     * @param {Object} [initialState={}] The values that the initial tween should
     * start at if a `from` value is not provided to {@link
     * Tweenable#tween} or {@link Tweenable#setConfig}.
     * @param {shifty.tweenConfig} [config] Configuration object to be passed to
     * {@link Tweenable#setConfig}.
     * @constructs Tweenable
     * @memberof shifty
     */
    constructor(initialState?: any, config?: shifty.tweenConfig);
    /** @private */
    private _config;
    /** @private */
    private _data;
    /** @private */
    private _delay;
    /** @private */
    private _filters;
    /** @private */
    private _next;
    /** @private */
    private _previous;
    /** @private */
    private _timestamp;
    /** @private */
    private _hasEnded;
    /** @private */
    private _resolve;
    /** @private */
    private _reject;
    /** @private */
    private _currentState;
    /** @private */
    private _originalState;
    /** @private */
    private _targetState;
    /** @private */
    private _start;
    /** @private */
    private _render;
    /** @private */
    private _promiseCtor;
    /**
     * Applies a filter to Tweenable instance.
     * @param {string} filterName The name of the filter to apply.
     * @private
     */
    private _applyFilter;
    /**
     * Configure and start a tween. If this {@link Tweenable}'s instance
     * is already running, then it will stop playing the old tween and
     * immediately play the new one.
     * @method Tweenable#tween
     * @param {shifty.tweenConfig} [config] Gets passed to {@link
     * Tweenable#setConfig}.
     * @return {Tweenable}
     */
    tween(config?: shifty.tweenConfig): Tweenable;
    /** @private */
    private _pausedAtTime;
    /**
     * Configure a tween that will start at some point in the future. Aside from
     * `delay`, `from`, and `to`, each configuration option will automatically
     * default to the same option used in the preceding tween of this {@link
     * Tweenable} instance.
     * @method Tweenable#setConfig
     * @param {shifty.tweenConfig} [config={}]
     * @return {Tweenable}
     */
    setConfig(config?: shifty.tweenConfig): Tweenable;
    /** @private */
    private _isPlaying;
    /** @private */
    private _scheduleId;
    /** @private */
    private _duration;
    /** @private */
    private _easing;
    /**
     * Overrides any `finish` function passed via a {@link shifty.tweenConfig}.
     * @method Tweenable#then
     * @param {function=} onFulfilled Receives {@link shifty.promisedData} as the
     * first parameter.
     * @param {function=} onRejected Receives {@link shifty.promisedData} as the
     * first parameter.
     * @return {Promise<Object>}
     * @see https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise/then
     */
    then(onFulfilled?: Function | undefined, onRejected?: Function | undefined): Promise<any>;
    /** @private */
    private _promise;
    /**
     * @method Tweenable#catch
     * @param {function} onRejected Receives {@link shifty.promisedData} as the
     * first parameter.
     * @return {Promise<Object>}
     * @see https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise/catch
     */
    catch(onRejected: Function): Promise<any>;
    /**
     * @method Tweenable#finally
     * @param {function} onFinally
     * @return {Promise<undefined>}
     * @see https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise/finally
     */
    finally(onFinally: Function): Promise<undefined>;
    /**
     * @method Tweenable#get
     * @return {Object} The current state.
     */
    get(): any;
    /**
     * Set the current state.
     * @method Tweenable#set
     * @param {Object} state The state to set.
     */
    set(state: any): void;
    /**
     * Pause a tween. Paused tweens can be resumed from the point at which they
     * were paused. If a tween is not running, this is a no-op.
     * @method Tweenable#pause
     * @return {Tweenable}
     */
    pause(): Tweenable;
    /**
     * Resume a paused tween.
     * @method Tweenable#resume
     * @return {Tweenable}
     */
    resume(): Tweenable;
    /**
     * @private
     * @param {number} currentTime
     * @returns {Tweenable}
     */
    private _resume;
    /**
     * Move the state of the animation to a specific point in the tween's
     * timeline.  If the animation is not running, this will cause {@link
     * shifty.renderFunction} handlers to be called.
     * @method Tweenable#seek
     * @param {number} millisecond The millisecond of the animation to seek
     * to.  This must not be less than `0`.
     * @return {Tweenable}
     */
    seek(millisecond: number): Tweenable;
    /**
     * Stops a tween. If a tween is not running, this is a no-op. This method
     * does not cancel the tween {@link external:Promise}. For that, use {@link
     * Tweenable#cancel}.
     * @param {boolean} [gotoEnd] If `false`, the tween just stops at its current
     * state.  If `true`, the tweened object's values are instantly set to the
     * target values.
     * @method Tweenable#stop
     * @return {Tweenable}
     */
    stop(gotoEnd?: boolean): Tweenable;
    /**
     * {@link Tweenable#stop}s a tween and also `reject`s its {@link
     * external:Promise}. If a tween is not running, this is a no-op. Prevents
     * calling any provided `finish` function.
     * @param {boolean} [gotoEnd] Is propagated to {@link Tweenable#stop}.
     * @method Tweenable#cancel
     * @return {Tweenable}
     * @see https://github.com/jeremyckahn/shifty/issues/122
     */
    cancel(gotoEnd?: boolean): Tweenable;
    /**
     * Whether or not a tween is running.
     * @method Tweenable#isPlaying
     * @return {boolean}
     */
    isPlaying(): boolean;
    /**
     * Whether or not a tween has finished running.
     * @method Tweenable#hasEnded
     * @return {boolean}
     */
    hasEnded(): boolean;
    /**
     * @method Tweenable#setScheduleFunction
     * @param {shifty.scheduleFunction} scheduleFunction
     * @deprecated Will be removed in favor of {@link Tweenable.setScheduleFunction} in 3.0.
     */
    setScheduleFunction(scheduleFunction: shifty.scheduleFunction): void;
    /**
     * Get and optionally set the data that gets passed as `data` to {@link
     * shifty.promisedData}, {@link shifty.startFunction} and {@link
     * shifty.renderFunction}.
     * @param {Object} [data]
     * @method Tweenable#data
     * @return {Object} The internally stored `data`.
     */
    data(data?: any): any;
    /**
     * `delete` all "own" properties.  Call this when the {@link
     * Tweenable} instance is no longer needed to free memory.
     * @method Tweenable#dispose
     */
    dispose(): void;
    [Symbol.toStringTag]: string;
}
export namespace shifty {
    type filter = import("./index").shifty.filter;
    type tweenConfig = import("./index").shifty.tweenConfig;
    type scheduleFunction = import("./index").shifty.scheduleFunction;
}
declare let scheduleFunction: any;
export {};
//# sourceMappingURL=tweenable.d.ts.map