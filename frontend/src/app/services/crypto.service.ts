import { Injectable } from '@angular/core';
import * as CryptoJS from 'crypto-js';

@Injectable({
  providedIn: 'root'
})
export class CryptoService {
  private secretKey = 'log-analyzer-soc-secret-key';

  encrypt(data: string): string {
    return CryptoJS.AES.encrypt(data, this.secretKey).toString();
  }

  decrypt(encryptedData: string): string {
    const bytes = CryptoJS.AES.decrypt(encryptedData, this.secretKey);
    return bytes.toString(CryptoJS.enc.Utf8);
  }

  encryptObject(obj: any): string {
    return this.encrypt(JSON.stringify(obj));
  }

  decryptObject(encryptedData: string): any {
    const decrypted = this.decrypt(encryptedData);
    return decrypted ? JSON.parse(decrypted) : null;
  }
}
