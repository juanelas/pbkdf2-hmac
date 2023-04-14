"use strict";require("crypto");const e={"SHA-1":{outputLength:20,blockSize:64},"SHA-256":{outputLength:32,blockSize:64},"SHA-384":{outputLength:48,blockSize:128},"SHA-512":{outputLength:64,blockSize:128}};module.exports=function(r,t,n,o,a="SHA-256"){return new Promise(((i,f)=>{a in e||f(new RangeError(`Valid hash algorithm values are any of ${Object.keys(e).toString()}`)),"string"==typeof r?r=(new TextEncoder).encode(r):r instanceof ArrayBuffer?r=new Uint8Array(r):ArrayBuffer.isView(r)||f(RangeError("P should be string, ArrayBuffer, TypedArray, DataView")),"string"==typeof t?t=(new TextEncoder).encode(t):t instanceof ArrayBuffer?t=new Uint8Array(t):ArrayBuffer.isView(t)?t=new Uint8Array(t.buffer,t.byteOffset,t.byteLength):f(RangeError("S should be string, ArrayBuffer, TypedArray, DataView"));{const e=a.toLowerCase().replace("-","");import("crypto").then((a=>{a.pbkdf2(r,t,n,o,e,((e,r)=>{null!=e?f(e):i(r.buffer)}))})).catch(f)}}))};
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5janMiLCJzb3VyY2VzIjpbIi4uL3NyYy90cy9pbmRleC50cyJdLCJzb3VyY2VzQ29udGVudCI6bnVsbCwibmFtZXMiOlsiSEFTSEFMR1MiLCJvdXRwdXRMZW5ndGgiLCJibG9ja1NpemUiLCJQIiwiUyIsImMiLCJka0xlbiIsImhhc2giLCJQcm9taXNlIiwicmVzb2x2ZSIsInJlamVjdCIsIlJhbmdlRXJyb3IiLCJPYmplY3QiLCJrZXlzIiwidG9TdHJpbmciLCJUZXh0RW5jb2RlciIsImVuY29kZSIsIkFycmF5QnVmZmVyIiwiVWludDhBcnJheSIsImlzVmlldyIsImJ1ZmZlciIsImJ5dGVPZmZzZXQiLCJieXRlTGVuZ3RoIiwibm9kZUFsZyIsInRvTG93ZXJDYXNlIiwicmVwbGFjZSIsImltcG9ydCIsInRoZW4iLCJjcnlwdG8iLCJwYmtkZjIiLCJlcnIiLCJkZXJpdmVkS2V5IiwiY2F0Y2giXSwibWFwcGluZ3MiOiIrQkFvQkEsTUFBTUEsRUFBcUIsQ0FDekIsUUFBUyxDQUFFQyxhQUFjLEdBQUlDLFVBQVcsSUFDeEMsVUFBVyxDQUFFRCxhQUFjLEdBQUlDLFVBQVcsSUFDMUMsVUFBVyxDQUFFRCxhQUFjLEdBQUlDLFVBQVcsS0FDMUMsVUFBVyxDQUFFRCxhQUFjLEdBQUlDLFVBQVcscUJBZ0JwQixTQUFZQyxFQUFpREMsRUFBaURDLEVBQVdDLEVBQWVDLEVBQWdCLFdBQzlLLE9BQU8sSUFBSUMsU0FBUSxDQUFDQyxFQUFTQyxLQUNyQkgsS0FBUVAsR0FDWlUsRUFBTyxJQUFJQyxXQUFXLDBDQUEwQ0MsT0FBT0MsS0FBS2IsR0FBVWMsZUFHdkUsaUJBQU5YLEVBQWdCQSxHQUFJLElBQUlZLGFBQWNDLE9BQU9iLEdBQy9DQSxhQUFhYyxZQUFhZCxFQUFJLElBQUllLFdBQVdmLEdBQzVDYyxZQUFZRSxPQUFPaEIsSUFBSU8sRUFBT0MsV0FBVywwREFFbEMsaUJBQU5QLEVBQWdCQSxHQUFJLElBQUlXLGFBQWNDLE9BQU9aLEdBQy9DQSxhQUFhYSxZQUFhYixFQUFJLElBQUljLFdBQVdkLEdBQzdDYSxZQUFZRSxPQUFPZixHQUFJQSxFQUFJLElBQUljLFdBQVdkLEVBQUVnQixPQUFRaEIsRUFBRWlCLFdBQVlqQixFQUFFa0IsWUFDeEVaLEVBQU9DLFdBQVcsMERBb0JoQixDQUNMLE1BQU1ZLEVBQVVoQixFQUFLaUIsY0FBY0MsUUFBUSxJQUFLLElBQ2hEQyxPQUFRLFVBQVVDLE1BQUtDLElBQ3JCQSxFQUFPQyxPQUFPMUIsRUFBNEJDLEVBQWlCQyxFQUFHQyxFQUFPaUIsR0FBUyxDQUFDTyxFQUFtQkMsS0FDckYsTUFBUEQsRUFBYXBCLEVBQU9vQixHQUNuQnJCLEVBQVFzQixFQUFXWCxPQUFPLEdBQy9CLElBQ0RZLE1BQU10QixFQUNWLElBRUwifQ==
