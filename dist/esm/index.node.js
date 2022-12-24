const e={"SHA-1":{outputLength:20,blockSize:64},"SHA-256":{outputLength:32,blockSize:64},"SHA-384":{outputLength:48,blockSize:128},"SHA-512":{outputLength:64,blockSize:128}};function r(r,t,n,o,a="SHA-256"){return new Promise(((f,i)=>{a in e||i(new RangeError(`Valid hash algorithm values are any of ${Object.keys(e).toString()}`)),"string"==typeof r?r=(new TextEncoder).encode(r):r instanceof ArrayBuffer?r=new Uint8Array(r):ArrayBuffer.isView(r)||i(RangeError("P should be string, ArrayBuffer, TypedArray, DataView")),"string"==typeof t?t=(new TextEncoder).encode(t):t instanceof ArrayBuffer?t=new Uint8Array(t):ArrayBuffer.isView(t)?t=new Uint8Array(t.buffer,t.byteOffset,t.byteLength):i(RangeError("S should be string, ArrayBuffer, TypedArray, DataView"));{const e=a.toLowerCase().replace("-","");import("crypto").then((a=>{a.pbkdf2(r,t,n,o,e,((e,r)=>{null!=e?i(e):f(r.buffer)}))})).catch(i)}}))}export{r as default};
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5qcyIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL3RzL2luZGV4LnRzIl0sInNvdXJjZXNDb250ZW50IjpudWxsLCJuYW1lcyI6WyJIQVNIQUxHUyIsIm91dHB1dExlbmd0aCIsImJsb2NrU2l6ZSIsInBia2RmMkhtYWMiLCJQIiwiUyIsImMiLCJka0xlbiIsImhhc2giLCJQcm9taXNlIiwicmVzb2x2ZSIsInJlamVjdCIsIlJhbmdlRXJyb3IiLCJPYmplY3QiLCJrZXlzIiwidG9TdHJpbmciLCJUZXh0RW5jb2RlciIsImVuY29kZSIsIkFycmF5QnVmZmVyIiwiVWludDhBcnJheSIsImlzVmlldyIsImJ1ZmZlciIsImJ5dGVPZmZzZXQiLCJieXRlTGVuZ3RoIiwibm9kZUFsZyIsInRvTG93ZXJDYXNlIiwicmVwbGFjZSIsImltcG9ydCIsInRoZW4iLCJjcnlwdG8iLCJwYmtkZjIiLCJlcnIiLCJkZXJpdmVkS2V5IiwiY2F0Y2giXSwibWFwcGluZ3MiOiJBQW9CQSxNQUFNQSxFQUFxQixDQUN6QixRQUFTLENBQUVDLGFBQWMsR0FBSUMsVUFBVyxJQUN4QyxVQUFXLENBQUVELGFBQWMsR0FBSUMsVUFBVyxJQUMxQyxVQUFXLENBQUVELGFBQWMsR0FBSUMsVUFBVyxLQUMxQyxVQUFXLENBQUVELGFBQWMsR0FBSUMsVUFBVyxNQWdCcEIsU0FBQUMsRUFBWUMsRUFBaURDLEVBQWlEQyxFQUFXQyxFQUFlQyxFQUFnQixXQUM5SyxPQUFPLElBQUlDLFNBQVEsQ0FBQ0MsRUFBU0MsS0FDckJILEtBQVFSLEdBQ1pXLEVBQU8sSUFBSUMsV0FBVywwQ0FBMENDLE9BQU9DLEtBQUtkLEdBQVVlLGVBR3ZFLGlCQUFOWCxFQUFnQkEsR0FBSSxJQUFJWSxhQUFjQyxPQUFPYixHQUMvQ0EsYUFBYWMsWUFBYWQsRUFBSSxJQUFJZSxXQUFXZixHQUM1Q2MsWUFBWUUsT0FBT2hCLElBQUlPLEVBQU9DLFdBQVcsMERBRWxDLGlCQUFOUCxFQUFnQkEsR0FBSSxJQUFJVyxhQUFjQyxPQUFPWixHQUMvQ0EsYUFBYWEsWUFBYWIsRUFBSSxJQUFJYyxXQUFXZCxHQUM3Q2EsWUFBWUUsT0FBT2YsR0FBSUEsRUFBSSxJQUFJYyxXQUFXZCxFQUFFZ0IsT0FBUWhCLEVBQUVpQixXQUFZakIsRUFBRWtCLFlBQ3hFWixFQUFPQyxXQUFXLDBEQW9CaEIsQ0FDTCxNQUFNWSxFQUFVaEIsRUFBS2lCLGNBQWNDLFFBQVEsSUFBSyxJQUNoREMsT0FBUSxVQUFVQyxNQUFLQyxJQUNyQkEsRUFBT0MsT0FBTzFCLEVBQTRCQyxFQUFpQkMsRUFBR0MsRUFBT2lCLEdBQVMsQ0FBQ08sRUFBbUJDLEtBQ3JGLE1BQVBELEVBQWFwQixFQUFPb0IsR0FDbkJyQixFQUFRc0IsRUFBV1gsT0FBTyxHQUMvQixJQUNEWSxNQUFNdEIsRUFDVixJQUVMIn0=
