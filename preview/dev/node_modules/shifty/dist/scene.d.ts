/** @typedef {import("./tweenable").Tweenable} Tweenable */
export class Scene {
    /**
     * The {@link Scene} class provides a way to control groups of {@link
     * Tweenable}s. It is lightweight, minimalistic, and meant to provide
     * performant {@link Tweenable} batch control that users of Shifty
     * might otherwise have to implement themselves. It is **not** a robust
     * timeline solution, and it does **not** provide utilities for sophisticated
     * animation sequencing or orchestration. If that is what you need for your
     * project, consider using a more robust tool such as
     * [Rekapi](http://jeremyckahn.github.io/rekapi/doc/) (a timeline layer built
     * on top of Shifty).
     *
     * Please be aware that {@link Scene} does **not** perform any
     * automatic cleanup. If you want to remove a {@link Tweenable} from a
     * {@link Scene}, you must do so explicitly with either {@link
     * Scene#remove} or {@link Scene#empty}.
     *
     * <p class="codepen" data-height="677" data-theme-id="0" data-default-tab="js,result" data-user="jeremyckahn" data-slug-hash="qvZKbe" style="height: 677px; box-sizing: border-box; display: flex; align-items: center; justify-content: center; border: 2px solid black; margin: 1em 0; padding: 1em;" data-pen-title="Shifty Scene Demo">
     * <span>See the Pen <a href="https://codepen.io/jeremyckahn/pen/qvZKbe/">
     * Shifty Scene Demo</a> by Jeremy Kahn (<a href="https://codepen.io/jeremyckahn">@jeremyckahn</a>)
     * on <a href="https://codepen.io">CodePen</a>.</span>
     * </p>
     * <script async src="https://static.codepen.io/assets/embed/ei.js"></script>
     * @param {...Tweenable} tweenables
     * @see https://codepen.io/jeremyckahn/pen/qvZKbe
     * @constructs Scene
     * @memberof shifty
     */
    constructor(...tweenables: Tweenable[]);
    /**
     * A copy of the internal {@link Tweenable}s array.
     * @member Scene#tweenables
     * @type {Array.<Tweenable>}
     */
    get tweenables(): import("./tweenable").Tweenable[];
    /**
     * A list of {@link Tweenable}s in the scene that have not yet ended (playing
     * or not).
     * @member Scene#playingTweenables
     * @type {Array.<Tweenable>}
     */
    get playingTweenables(): import("./tweenable").Tweenable[];
    /**
     * The {@link external:Promise}s for all {@link Tweenable}s in this
     * {@link Scene} that have been configured with {@link
     * Tweenable#setConfig}. Note that each call of {@link
     * Scene#play} or {@link Scene#pause} creates new {@link
     * external:Promise}s:
     *
     *     const scene = new Scene(new Tweenable());
     *     scene.play();
     *
     *     Promise.all(scene.promises).then(() =>
     *       // Plays the scene again upon completion, but a new promise is
     *       // created so this line only runs once.
     *       scene.play()
     *     );
     *
     * @member Scene#promises
     * @type {Array.<Promise<any>>}
     */
    get promises(): Promise<any>[];
    /**
     * Add a {@link Tweenable} to be controlled by this {@link
     * Scene}.
     * @method Scene#add
     * @param {Tweenable} tweenable
     * @return {Tweenable} The {@link Tweenable} that was added.
     */
    add(tweenable: Tweenable): Tweenable;
    /**
     * Remove a {@link Tweenable} that is controlled by this {@link
     * Scene}.
     * @method Scene#remove
     * @param {Tweenable} tweenable
     * @return {Tweenable} The {@link Tweenable} that was removed.
     */
    remove(tweenable: Tweenable): Tweenable;
    /**
     * [Remove]{@link Scene#remove} all {@link Tweenable}s in this {@link
     * Scene}.
     * @method Scene#empty
     * @return {Array.<Tweenable>} The {@link Tweenable}s that were
     * removed.
     */
    empty(): Array<Tweenable>;
    /**
     * Is `true` if any {@link Tweenable} in this {@link Scene} is
     * playing.
     * @method Scene#isPlaying
     * @return {boolean}
     */
    isPlaying(): boolean;
    /**
     * Play all {@link Tweenable}s from their beginning.
     * @method Scene#play
     * @return {Scene}
     */
    play(): Scene;
    /**
     * {@link Tweenable#pause} all {@link Tweenable}s in this
     * {@link Scene}.
     * @method Scene#pause
     * @return {Scene}
     */
    pause(): Scene;
    /**
     * {@link Tweenable#resume} all paused {@link Tweenable}s.
     * @method Scene#resume
     * @return {Scene}
     */
    resume(): Scene;
    /**
     * {@link Tweenable#stop} all {@link Tweenable}s in this {@link
     * Scene}.
     * @method Scene#stop
     * @param {boolean} [gotoEnd]
     * @return {Scene}
     */
    stop(gotoEnd?: boolean): Scene;
    #private;
}
export type Tweenable = import("./tweenable").Tweenable;
//# sourceMappingURL=scene.d.ts.map