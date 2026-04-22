import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { HttpClient } from '@angular/common/http';
import { SidebarComponent } from '../../sidebar/sidebar.component';
import { environment } from '../../../../environments/environment';

@Component({
  selector: 'app-remote-console',
  standalone: true,
  imports: [CommonModule, FormsModule, SidebarComponent],
  template: `
    <div class="flex h-screen bg-slate-900 text-white">
      <app-sidebar></app-sidebar>

      <main class="flex-1 ml-64 flex flex-col p-8">
        <header class="mb-6">
          <h2 class="text-2xl font-bold text-indigo-400 flex items-center gap-3">
            <i class="fas fa-terminal"></i>
            Console SSH Sécurisée
          </h2>
          <p class="text-slate-400 text-sm mt-1">Accès direct aux serveurs distants pour administration rapide</p>
        </header>

        <div class="grid grid-cols-4 gap-6 mb-6">
          <div class="col-span-1 space-y-4 bg-slate-800 p-6 rounded-xl border border-slate-700 shadow-xl">
            <h3 class="font-bold text-slate-300 border-b border-slate-700 pb-2 mb-4">Connexion</h3>
            
            <div>
              <label class="block text-xs font-bold text-slate-500 uppercase mb-1">Hôte (&#64;IP)</label>
              <input type="text" [(ngModel)]="ssh.host" 
                     class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm focus:ring-1 focus:ring-indigo-500 outline-none">
            </div>

            <div>
              <label class="block text-xs font-bold text-slate-500 uppercase mb-1">Utilisateur</label>
              <input type="text" [(ngModel)]="ssh.user" 
                     class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm focus:ring-1 focus:ring-indigo-500 outline-none">
            </div>

            <div>
              <label class="block text-xs font-bold text-slate-500 uppercase mb-1">Mot de passe</label>
              <input type="password" [(ngModel)]="ssh.pass" 
                     class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm focus:ring-1 focus:ring-indigo-500 outline-none">
            </div>

            <div class="pt-4">
              <button (click)="clearConsole()" 
                      class="w-full px-4 py-2 bg-slate-700 hover:bg-slate-600 rounded-lg transition text-sm font-bold">
                Effacer Console
              </button>
            </div>
          </div>

          <div class="col-span-3 flex flex-col bg-black rounded-xl border border-slate-700 shadow-2xl overflow-hidden min-h-[500px]">
            <!-- Terminal Output -->
            <!-- Sortie du terminal -->
            <div class="flex-1 p-6 font-mono text-sm overflow-auto text-emerald-400 bg-black/90" #terminalBody>
              <div *ngFor="let line of history" class="mb-1">
                <span class="text-indigo-400 font-bold">$ {{ line.cmd }}</span>
                <pre class="mt-1 whitespace-pre-wrap text-slate-300">{{ line.output }}</pre>
                <pre *ngIf="line.error" class="mt-1 whitespace-pre-wrap text-red-400">{{ line.error }}</pre>
              </div>
              <div *ngIf="loading" class="flex items-center gap-2 text-indigo-400">
                <i class="fas fa-spinner fa-spin"></i>
                <span>Exécution de la commande...</span>
              </div>
            </div>

            <!-- Terminal Input -->
            <!-- Entrée du terminal -->
            <div class="p-4 bg-slate-900 border-t border-slate-800 flex items-center gap-3">
              <span class="text-indigo-500 font-bold font-mono">$</span>
              <input type="text" [(ngModel)]="command" (keyup.enter)="executeCommand()" [disabled]="loading"
                     placeholder="Entrez votre commande Linux ici..."
                     class="flex-1 bg-transparent outline-none font-mono text-indigo-400 text-sm">
              <button (click)="executeCommand()" [disabled]="loading"
                      class="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg transition text-xs font-bold uppercase tracking-wider">
                Exécuter
              </button>
            </div>
          </div>
        </div>
      </main>
    </div>
  `
})
export class RemoteConsoleComponent {
  ssh = { host: '', user: '', pass: '' };
  command = '';
  history: { cmd: string; output: string; error?: string }[] = [];
  loading = false;
  private apiUrl = environment.apiUrl;

  constructor(private http: HttpClient) {}

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
