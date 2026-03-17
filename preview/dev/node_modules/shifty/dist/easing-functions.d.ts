/** @typedef {import(".").shifty.easingFunction} shifty.easingFunction */
/*!
 * All equations are adapted from Thomas Fuchs'
 * [Scripty2](https://github.com/madrobby/scripty2/blob/master/src/effects/transitions/penner.js).
 *
 * Based on Easing Equations (c) 2003 [Robert
 * Penner](http://www.robertpenner.com/), all rights reserved. This work is
 * [subject to terms](http://www.robertpenner.com/easing_terms_of_use.html).
 */
/*!
 *  TERMS OF USE - EASING EQUATIONS
 *  Open source under the BSD License.
 *  Easing Equations (c) 2003 Robert Penner, all rights reserved.
 */
/**
 * @member Tweenable.formulas
 * @description A static Object of {@link shifty.easingFunction}s that can by
 * used by Shifty. The default values are defined in
 * [`easing-functions.js`](easing-functions.js.html), but you can add your own
 * {@link shifty.easingFunction}s by defining them as keys to this Object.
 *
 * Shifty ships with an implementation of [Robert Penner's easing
 * equations](http://robertpenner.com/easing/), as adapted from
 * [Scripty2](https://github.com/madrobby/scripty2/blob/master/src/effects/transitions/penner.js)'s
 * implementation.
 * <p data-height="934" data-theme-id="0" data-slug-hash="wqObdO"
 * data-default-tab="js,result" data-user="jeremyckahn" data-embed-version="2"
 * data-pen-title="Shifty - Easing formula names" class="codepen">See the Pen <a
 * href="https://codepen.io/jeremyckahn/pen/wqObdO/">Shifty - Easing formula
 * names</a> by Jeremy Kahn (<a
 * href="https://codepen.io/jeremyckahn">@jeremyckahn</a>) on <a
 * href="https://codepen.io">CodePen</a>.</p>
 * <script async
 * src="https://production-assets.codepen.io/assets/embed/ei.js"></script>
 * @type {Object.<shifty.easingFunction>}
 * @static
 */
/**
 * @memberof Tweenable.formulas
 * @type {shifty.easingFunction}
 * @param {number} pos
 * @returns {number}
 */
export const linear: shifty.easingFunction;
/**
 * @memberof Tweenable.formulas
 * @type {shifty.easingFunction}
 * @param {number} pos
 * @returns {number}
 */
export const easeInQuad: shifty.easingFunction;
/**
 * @memberof Tweenable.formulas
 * @type {shifty.easingFunction}
 * @param {number} pos
 * @returns {number}
 */
export const easeOutQuad: shifty.easingFunction;
/**
 * @memberof Tweenable.formulas
 * @type {shifty.easingFunction}
 * @param {number} pos
 * @returns {number}
 */
export const easeInOutQuad: shifty.easingFunction;
/**
 * @memberof Tweenable.formulas
 * @type {shifty.easingFunction}
 * @param {number} pos
 * @returns {number}
 */
export const easeInCubic: shifty.easingFunction;
/**
 * @memberof Tweenable.formulas
 * @type {shifty.easingFunction}
 * @param {number} pos
 * @returns {number}
 */
export const easeOutCubic: shifty.easingFunction;
/**
 * @memberof Tweenable.formulas
 * @type {shifty.easingFunction}
 * @param {number} pos
 * @returns {number}
 */
export const easeInOutCubic: shifty.easingFunction;
/**
 * @memberof Tweenable.formulas
 * @type {shifty.easingFunction}
 * @param {number} pos
 * @returns {number}
 */
export const easeInQuart: shifty.easingFunction;
/**
 * @memberof Tweenable.formulas
 * @type {shifty.easingFunction}
 * @param {number} pos
 * @returns {number}
 */
export const easeOutQuart: shifty.easingFunction;
/**
 * @memberof Tweenable.formulas
 * @type {shifty.easingFunction}
 * @param {number} pos
 * @returns {number}
 */
export const easeInOutQuart: shifty.easingFunction;
/**
 * @memberof Tweenable.formulas
 * @type {shifty.easingFunction}
 * @param {number} pos
 * @returns {number}
 */
export const easeInQuint: shifty.easingFunction;
/**
 * @memberof Tweenable.formulas
 * @type {shifty.easingFunction}
 * @param {number} pos
 * @returns {number}
 */
export const easeOutQuint: shifty.easingFunction;
/**
 * @memberof Tweenable.formulas
 * @type {shifty.easingFunction}
 * @param {number} pos
 * @returns {number}
 */
export const easeInOutQuint: shifty.easingFunction;
/**
 * @memberof Tweenable.formulas
 * @type {shifty.easingFunction}
 * @param {number} pos
 * @returns {number}
 */
export const easeInSine: shifty.easingFunction;
/**
 * @memberof Tweenable.formulas
 * @type {shifty.easingFunction}
 * @param {number} pos
 * @returns {number}
 */
export const easeOutSine: shifty.easingFunction;
/**
 * @memberof Tweenable.formulas
 * @type {shifty.easingFunction}
 * @param {number} pos
 * @returns {number}
 */
export const easeInOutSine: shifty.easingFunction;
/**
 * @memberof Tweenable.formulas
 * @type {shifty.easingFunction}
 * @param {number} pos
 * @returns {number}
 */
export const easeInExpo: shifty.easingFunction;
/**
 * @memberof Tweenable.formulas
 * @type {shifty.easingFunction}
 * @param {number} pos
 * @returns {number}
 */
export const easeOutExpo: shifty.easingFunction;
/**
 * @memberof Tweenable.formulas
 * @type {shifty.easingFunction}
 * @param {number} pos
 * @returns {number}
 */
export const easeInOutExpo: shifty.easingFunction;
/**
 * @memberof Tweenable.formulas
 * @type {shifty.easingFunction}
 * @param {number} pos
 * @returns {number}
 */
export const easeInCirc: shifty.easingFunction;
/**
 * @memberof Tweenable.formulas
 * @type {shifty.easingFunction}
 * @param {number} pos
 * @returns {number}
 */
export const easeOutCirc: shifty.easingFunction;
/**
 * @memberof Tweenable.formulas
 * @type {shifty.easingFunction}
 * @param {number} pos
 * @returns {number}
 */
export const easeInOutCirc: shifty.easingFunction;
/**
 * @memberof Tweenable.formulas
 * @type {shifty.easingFunction}
 * @param {number} pos
 * @returns {number}
 */
export const easeOutBounce: shifty.easingFunction;
/**
 * @memberof Tweenable.formulas
 * @type {shifty.easingFunction}
 * @param {number} pos
 * @returns {number}
 */
export const easeInBack: shifty.easingFunction;
/**
 * @memberof Tweenable.formulas
 * @type {shifty.easingFunction}
 * @param {number} pos
 * @returns {number}
 */
export const easeOutBack: shifty.easingFunction;
/**
 * @memberof Tweenable.formulas
 * @type {shifty.easingFunction}
 * @param {number} pos
 * @returns {number}
 */
export const easeInOutBack: shifty.easingFunction;
/**
 * @memberof Tweenable.formulas
 * @type {shifty.easingFunction}
 * @param {number} pos
 * @returns {number}
 */
export const elastic: shifty.easingFunction;
/**
 * @memberof Tweenable.formulas
 * @type {shifty.easingFunction}
 * @param {number} pos
 * @returns {number}
 */
export const swingFromTo: shifty.easingFunction;
/**
 * @memberof Tweenable.formulas
 * @type {shifty.easingFunction}
 * @param {number} pos
 * @returns {number}
 */
export const swingFrom: shifty.easingFunction;
/**
 * @memberof Tweenable.formulas
 * @type {shifty.easingFunction}
 * @param {number} pos
 * @returns {number}
 */
export const swingTo: shifty.easingFunction;
/**
 * @memberof Tweenable.formulas
 * @type {shifty.easingFunction}
 * @param {number} pos
 * @returns {number}
 */
export const bounce: shifty.easingFunction;
/**
 * @memberof Tweenable.formulas
 * @type {shifty.easingFunction}
 * @param {number} pos
 * @returns {number}
 */
export const bouncePast: shifty.easingFunction;
/**
 * @memberof Tweenable.formulas
 * @type {shifty.easingFunction}
 * @param {number} pos
 * @returns {number}
 */
export const easeFromTo: shifty.easingFunction;
/**
 * @memberof Tweenable.formulas
 * @type {shifty.easingFunction}
 * @param {number} pos
 * @returns {number}
 */
export const easeFrom: shifty.easingFunction;
/**
 * @memberof Tweenable.formulas
 * @type {shifty.easingFunction}
 * @param {number} pos
 * @returns {number}
 */
export const easeTo: shifty.easingFunction;
export namespace shifty {
    type easingFunction = import(".").shifty.easingFunction;
}
//# sourceMappingURL=easing-functions.d.ts.map