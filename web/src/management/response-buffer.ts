const blockBytes = 64 << 10;

// WebSocket fragment count is attacker-controlled. Own fixed-size slabs rather
// than one retained JS object/allocation per frame; maximum also bounds slack.
export class ManagementResponseBuffer {
  readonly #maximum: number;
  readonly #allocate: (length: number) => Uint8Array<ArrayBuffer>;
  #blocks: Uint8Array<ArrayBuffer>[] = [];
  #length = 0;
  constructor(maximum: number, allocate = (length: number) => new Uint8Array(length)) {
    if (!Number.isSafeInteger(maximum) || maximum < 1) {
      throw new Error('invalid management response bound');
    }
    this.#maximum = maximum;
    this.#allocate = allocate;
  }
  append(data: Uint8Array): void {
    if (data.byteLength > this.#maximum - this.#length) {
      throw new Error('management response bound exceeded');
    }
    let position = 0;
    while (position < data.byteLength) {
      const index = Math.floor(this.#length / blockBytes);
      const offset = this.#length % blockBytes;
      let block = this.#blocks[index];
      if (!block) {
        block = this.#allocate(Math.min(blockBytes, this.#maximum - index * blockBytes));
        this.#blocks.push(block);
      }
      const length = Math.min(block.byteLength - offset, data.byteLength - position);
      block.set(data.subarray(position, position + length), offset);
      position += length;
      this.#length += length;
    }
  }
  assemble(): ArrayBuffer {
    let output: Uint8Array<ArrayBuffer> | undefined;
    let completed = false;
    try {
      output = this.#allocate(this.#length);
      let offset = 0;
      for (const block of this.#blocks) {
        const length = Math.min(block.byteLength, this.#length - offset);
        output.set(block.subarray(0, length), offset);
        offset += length;
      }
      completed = true;
      return output.buffer;
    } finally {
      this.wipe();
      if (!completed) {
        output?.fill(0);
      }
    }
  }
  wipe(): void {
    for (const block of this.#blocks) {
      block.fill(0);
    }
    this.#blocks = [];
    this.#length = 0;
  }
}
