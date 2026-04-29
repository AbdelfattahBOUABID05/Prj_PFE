import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { HttpClient } from '@angular/common/http';
import { SidebarComponent } from '../../sidebar/sidebar.component';
import { environment } from '../../../../environments/environment';

@Component({
  selector: 'app-remote-console',
  standalone: true,
  imports: [CommonModule, FormsModule, SidebarComponent],
  templateUrl: './remote-console.component.html',
  styleUrls: ['./remote-console.component.css']
})
export class RemoteConsoleComponent implements OnInit {
  ssh = { host: '', user: '', pass: '' };
  command = '';
  history: { cmd: string; output: string; error?: string }[] = [];
  loading = false;
  recentConnections: any[] = [];
  private apiUrl = environment.apiUrl;

  constructor(private http: HttpClient) {}

  ngOnInit(): void {
    this.loadRecent();
  }

  loadRecent(): void {
    this.http.get<any>(`${this.apiUrl}/admin/console/recent`).subscribe({
      next: (res) => {
        if (res.status === 'success') {
          this.recentConnections = res.connections;
        }
      },
      error: (err) => console.error('Erreur chargement connexions admin:', err)
    });
  }

  fillForm(conn: any): void {
    this.ssh.host = conn.host;
    this.ssh.user = conn.username;
    this.ssh.pass = conn.password;
  }

  executeCommand(): void {
    if (!this.command.trim() || !this.ssh.host || !this.ssh.user || !this.ssh.pass) {
      alert(`Veuillez remplir tous les champs de connexion et la commande.`);
      return;
    }

    const currentCmd = this.command;
    this.loading = true;
    this.command = '';

    this.http.post<any>(`${this.apiUrl}/admin/console`, {
      ...this.ssh,
      command: currentCmd
    }).subscribe({
      next: (res) => {
        this.history.push({
          cmd: currentCmd,
          output: res.output,
          error: res.error
        });
        this.loading = false;
        this.scrollToBottom();
        // Recharger les connexions récentes après un succès
        this.loadRecent();
      },
      error: (err) => {
        this.history.push({
          cmd: currentCmd,
          output: '',
          error: err.error?.message || `Erreur de connexion`
        });
        this.loading = false;
        this.scrollToBottom();
      }
    });
  }

  clearConsole(): void {
    this.history = [];
  }

  private scrollToBottom(): void {
    setTimeout(() => {
      const terminal = document.querySelector('.overflow-auto');
      if (terminal) terminal.scrollTop = terminal.scrollHeight;
    }, 100);
  }
}
