import { EvidenceError } from './evidence-protocol';
import type { PlaybackImage } from './playback-protocol';

// Explicit, single-use transfer. Before take(), the preparation owns the image.
// Afterwards only RecordingPlayback may dispose it; a parent cleanup cannot
// wipe bytes still owned by an asynchronous renderer.
export class PreparedPlayback {
    #image: PlaybackImage | null;
    constructor(image: PlaybackImage) {
        this.#image = image;
    }
    take(): PlaybackImage {
        const image = this.#image;
        if (!image) {
            throw new EvidenceError('cancelled');
        }
        this.#image = null;
        return image;
    }
    dispose(): void {
        const image = this.#image;
        this.#image = null;
        image?.dispose();
    }
}
