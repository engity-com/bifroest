// One owned browser download URL, never a persisted or server-side plaintext
// sink. A click requests saving; it does not prove a successful filesystem write.
export class LocalArtifactDownload {
  #url: string | null = null;

  clear() {
    if (this.#url !== null) {
      URL.revokeObjectURL(this.#url);
      this.#url = null;
    }
  }

  save(data: Blob, filename: string) {
    this.clear();
    if (!/^[A-Za-z0-9.-]{1,240}$/u.test(filename) || filename === '.' || filename === '..') {
      throw new Error('invalid local artifact filename');
    }
    const url = URL.createObjectURL(data);
    this.#url = url;
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = filename;
    anchor.rel = 'noopener noreferrer';
    try {
      document.body.append(anchor);
      anchor.click();
    } catch {
      this.clear();
      throw new Error('local artifact save unavailable');
    } finally {
      anchor.remove();
    }
  }
}
