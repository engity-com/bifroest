export const validSigningID = (value: string) =>
    /^[0-9a-f]{64}$/u.test(value) && !/^0+$/u.test(value);
