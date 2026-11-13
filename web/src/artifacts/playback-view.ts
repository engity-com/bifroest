export function fitPlaybackViewport(
    width: number,
    height: number,
    boxWidth: number,
    boxHeight: number,
) {
    if (
        ![width, height, boxWidth, boxHeight].every((value) => Number.isFinite(value) && value > 0)
    ) {
        return null;
    }
    const scale = Math.min(boxWidth / width, boxHeight / height);
    return { scale, left: (boxWidth - width * scale) / 2, top: (boxHeight - height * scale) / 2 };
}

export function playbackClock(positionUs: number): string {
    const seconds = Number.isFinite(positionUs)
        ? Math.max(0, Math.floor(positionUs / 1_000_000))
        : 0;
    const minutes = Math.floor(seconds / 60);
    const tail = String(seconds % 60).padStart(2, '0');
    return minutes >= 60
        ? `${Math.floor(minutes / 60)}:${String(minutes % 60).padStart(2, '0')}:${tail}`
        : `${minutes}:${tail}`;
}

export const playbackSpeeds = [0.25, 0.5, 0.75, 1, 1.25, 1.5, 2, 4, 8] as const;
