export const base64UrlToBase64Std = (baseText: string): string => {
  return baseText.replace(/-/g, "+").replace(/_/g, "/");
};

export const base64StdToArrayBuffers = (baseText: string): Uint8Array<ArrayBuffer> => {
  return Uint8Array.from(atob(baseText), c => c.charCodeAt(0));
};