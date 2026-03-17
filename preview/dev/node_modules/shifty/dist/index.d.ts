export { interpolate } from "./interpolate";
export { Scene } from "./scene";
export namespace shifty {
    type easingFunction = (position: number) => number;
    type startFunction = (state: any, data?: any | undefined) => void;
    type finishFunction = (promisedData: shifty.promisedData) => void;
    /**
     * Gets called for every tick of the tween.  This function is not called on the
     * final tick of the animation.
     */
    type renderFunction = (state: any, data: any | undefined, timeElapsed: number) => void;
    type scheduleFunction = (callback: Function, timeout: number) => void;
    type tweenConfig = {
        /**
         * Starting position.  If omitted, {@link * Tweenable#get} is used.
         */
        from?: any;
        /**
         * Ending position.  The keys of this Object should
         * match those of `to`.
         */
        to?: any;
        /**
         * How many milliseconds to animate for.
         */
        duration?: number;
        /**
         * How many milliseconds to wait before starting the
         * tween.
         */
        delay?: number;
        /**
         * Executes when the tween begins.
         */
        start?: shifty.startFunction;
        /**
         * Executes when the tween
         * completes. This will get overridden by {@link Tweenablethen } if that
         * is called, and it will not fire if {@link Tweenablecancel } is
         * called.
         */
        finish?: shifty.finishFunction;
        /**
         * Executes on every tick. Shifty
         * assumes a [retained mode](https://en.wikipedia.org/wiki/Retained_mode)
         * rendering environment, which in practice means that `render` only gets
         * called when the tween state changes. Importantly, this means that `render`
         * is _not_ called when a tween is not animating (for instance, when it is
         * paused or waiting to start via the `delay` option). This works naturally
         * with DOM environments, but you may need to account for this design in more
         * custom environments such as `<canvas>`.
         *
         * Legacy property name: `step`.
         */
        render?: shifty.renderFunction;
        /**
         * - `string`: Name of the {@link Tweenable.formulas } to apply to all
         * properties of the tween.
         * - {@link shifty.easingFunction }: A custom function that computes the rendered
         * position of the tween for the given normalized position of the tween.
         * - `Object`: Keys are tween property names. Values are the {@link *   Tweenable.formulas} to be applied to each tween property, or a {@link *   shifty.easingFunction}. Any tween properties not included in the `Object`
         * default to `'linear'`.
         * - `Array.<number>`: The array must contain four `number` values that
         * correspond to the `[x1, y1, x2, y2]` values of a [Bezier
         * curve](https://cubic-bezier.com/).
         *
         * You can learn more about this in the {@tutorial
         * easing-function-in-depth} tutorial.
         */
        easing?: string | shifty.easingFunction | any | Array<number>;
        /**
         * Data that is passed to {@link * shifty.startFunction}, {@link shifty.renderFunction }, and {@link * shifty.promisedData}. Legacy property name: `attachment`.
         */
        data?: any;
        /**
         * Promise constructor for when you want
         * to use Promise library or polyfill Promises in unsupported environments.
         */
        promise?: Function;
    };
    type promisedData = {
        /**
         * The current state of the tween.
         */
        state: any;
        /**
         * The `data` Object that the tween was configured with.
         */
        data: any;
        /**
         * The {@link Tweenable } instance to
         * which the tween belonged.
         */
        tweenable: Tweenable;
    };
    /**
     * Is called when a tween is created to determine if a filter is needed.
     * Filters are only added to a tween when it is created so that they are not
     * unnecessarily processed if they don't apply during an update tick.
     */
    type doesApplyFilter = (tweenable: Tweenable) => boolean;
    /**
     * Is called when a tween is created.  This should perform any setup needed by
     * subsequent per-tick calls to {@link shifty.beforeTween } and {@link * shifty.afterTween}.
     */
    type tweenCreatedFilter = (tweenable: Tweenable) => void;
    /**
     * Is called right before a tween is processed in a tick.
     */
    type beforeTweenFilter = (tweenable: Tweenable) => void;
    /**
     * Is called right after a tween is processed in a tick.
     */
    type afterTweenFilter = (tweenable: Tweenable) => void;
    /**
     * An Object that contains functions that are called at key points in a tween's
     * lifecycle.  Shifty can only process `Number`s internally, but filters can
     * expand support for any type of data.  This is the mechanism that powers
     * [string interpolation]{@tutorial string-interpolation}.
     */
    type filter = {
        /**
         * Is called when a tween is
         * created.
         */
        doesApply: shifty.doesApplyFilter;
        /**
         * Is called when a tween is
         * created.
         */
        tweenCreated: shifty.tweenCreatedFilter;
        /**
         * Is called right before a
         * tween starts.
         */
        beforeTween: shifty.beforeTweenFilter;
        /**
         * Is called right after a tween
         * ends.
         */
        afterTween: shifty.afterTweenFilter;
    };
}
import { processTweens } from "./tweenable";
import { shouldScheduleUpdate } from "./tweenable";
import { Tweenable } from "./tweenable";
import { tween } from "./tweenable";
export { processTweens, shouldScheduleUpdate, Tweenable, tween };
export { setBezierFunction, unsetBezierFunction } from "./bezier";
//# sourceMappingURL=index.d.ts.map