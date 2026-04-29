import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterModule } from '@angular/router';
import { HttpClient } from '@angular/common/http';
import { environment } from '../../../environments/environment';
import { LogService, SettingsPayload } from '../../services/log.service';
import { SidebarComponent } from '../sidebar/sidebar.component';

@Component({
  selector: 'app-settings',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterModule, SidebarComponent],
  templateUrl: './settings.component.html',
  styleUrls: ['./settings.component.css']
})
export class SettingsComponent implements OnInit {
  settings: SettingsPayload = {
    emailNotifications: false,
    notificationEmail: '',
    smtpServer: 'smtp.gmail.com',
    smtpPort: 587,
    smtpUser: '',
    smtpPassword: ''
  };

  loading: boolean = false;
  showAdvanced: boolean = false;
  username: string = 'analyste';

  constructor(private logService: LogService, private http: HttpClient) {}

  ngOnInit(): void {
    this.loadSettings();
    this.loadProfile();
  }

  loadSettings(): void {
    this.logService.getSettings().subscribe({
      next: (response: any) => {
        if (response.status === 'success' && response.settings) {
          this.settings = {
            ...response.settings,
            smtpPassword: ''
          };
        }
      },
      error: (err: any) => console.error('Settings load error:', err)
    });
  }

  loadProfile(): void {
    const apiUrl = environment.apiUrl;
    this.http.get<any>(`${apiUrl}/profile`).subscribe({
      next: (res: any) => {
        this.username = res.username || 'analyste';
      },
      error: (err: any) => console.error('Profile load error:', err)
    });
  }

  saveSettings(): void {
    this.loading = true;
    this.logService.saveSettings(this.settings).subscribe({
      next: (response: any) => {
        this.loading = false;
        alert(response.message || 'Paramètres enregistrés avec succès !');
      },
      error: (err: any) => {
        this.loading = false;
        const message = err?.error?.message || 'Erreur lors de la sauvegarde des paramètres';
        alert(message);
      }
    });
  }
}
