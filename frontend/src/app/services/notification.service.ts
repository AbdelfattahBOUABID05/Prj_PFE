import { Injectable } from '@angular/core';
import { ToastrService } from 'ngx-toastr';
import Swal, { SweetAlertIcon, SweetAlertOptions } from 'sweetalert2';

@Injectable({
  providedIn: 'root'
})
export class NotificationService {

  // Configuration par défaut pour le Dark Mode SOC
  private swalDarkOptions: SweetAlertOptions = {
    background: '#161b22',
    color: '#c9d1d9',
    confirmButtonColor: '#4f46e5', // Indigo-600
    cancelButtonColor: '#30363d',
    customClass: {
      popup: 'border border-white/10 rounded-3xl shadow-2xl',
      title: 'text-white font-bold',
      confirmButton: 'rounded-xl px-6 py-3 font-bold uppercase tracking-widest text-xs',
      cancelButton: 'rounded-xl px-6 py-3 font-bold uppercase tracking-widest text-xs'
    }
  };

  constructor(private toastr: ToastrService) { }

  /**
   * Modale de confirmation stylisée SOC
   */
  async confirm(title: string, text: string, icon: SweetAlertIcon = 'warning'): Promise<boolean> {
    const result = await Swal.fire({
      ...this.swalDarkOptions,
      title,
      text,
      icon,
      showCancelButton: true,
      confirmButtonText: 'Confirmer',
      cancelButtonText: 'Annuler',
      reverseButtons: true
    });
    return result.isConfirmed;
  }

  /**
   * Modale d'alerte simple
   */
  alert(title: string, text: string, icon: SweetAlertIcon = 'info'): void {
    Swal.fire({
      ...this.swalDarkOptions,
      title,
      text,
      icon,
      confirmButtonText: 'OK'
    });
  }

  /**
   * Modale de saisie de texte (ex: motif de refus)
   */
  async prompt(title: string, placeholder: string, inputType: 'text' | 'textarea' = 'text'): Promise<string | null> {
    const result = await Swal.fire({
      ...this.swalDarkOptions,
      title,
      input: inputType,
      inputPlaceholder: placeholder,
      showCancelButton: true,
      confirmButtonText: 'Valider',
      cancelButtonText: 'Annuler',
      inputValidator: (value) => {
        if (!value) {
          return 'Ce champ est requis !';
        }
        return null;
      }
    });
    return result.isConfirmed ? result.value : null;
  }

  /**
   * Notifications Toastr (Feedback rapide)
   */
  success(message: string, title: string = 'Succès'): void {
    this.toastr.success(message, title, { timeOut: 3000, progressBar: true });
  }

  error(message: string, title: string = 'Erreur'): void {
    this.toastr.error(message, title, { timeOut: 5000, progressBar: true });
  }

  warning(message: string, title: string = 'Attention'): void {
    this.toastr.warning(message, title, { timeOut: 4000, progressBar: true });
  }

  info(message: string, title: string = 'Information'): void {
    this.toastr.info(message, title, { timeOut: 3000, progressBar: true });
  }
}
