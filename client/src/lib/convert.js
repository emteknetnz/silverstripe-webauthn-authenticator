export const base64ToByteArray = string => {
  // String replace because server with encode with 'web safe' base64_encode
  const b = atob(string.replace(/_/g, '/').replace(/-/g, '+'));
  return Uint8Array.from(b, c => c.charCodeAt(0));
};

export const byteArrayToBase64 = byteArray => {
  // We specifically do not want to make the 'web safe' string replacements above
  // doing so will break this functionality
  const uarr = new Uint8Array(byteArray);
  return btoa(String.fromCharCode(...uarr));
};
