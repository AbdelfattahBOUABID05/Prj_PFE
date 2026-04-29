import { Component, OnInit, ViewChild, ElementRef, AfterViewChecked } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ReactiveFormsModule, FormBuilder, FormGroup, Validators } from '@angular/forms';
import { RouterModule } from '@angular/router';
import { LogService } from '../../services/log.service';
import { SidebarComponent } from '../sidebar/sidebar.component';

@Component({
  selector: 'app-ssh-connection',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule, RouterModule, SidebarComponent],
  templateUrl: './ssh.component.html',
  styleUrls: ['./ssh.component.css']
})
export class SshComponent implements OnInit, AfterViewChecked {
  @ViewChild('terminalContainer') private terminalContainer!: ElementRef;

  sshForm: FormGroup;
  loading = false;
  error = '';
  success = false;
  showPassword = false;
  lastAnalysisId: number | null = null;
  recentConnections: any[] = [];
  
  // SOC UI Variables
  terminalLogs: string[] = [];

  constructor(private fb: FormBuilder, private logService: LogService) {
    this.sshForm = this.fb.group({
      host: ['', [Validators.required]],
      user: ['', [Validators.required]],
      pass: ['', [Validators.required]],
      filePath: ['/var/log/syslog', [Validators.required]],
      numLines: [],
      auditDate: ['']
    });
  }

  ngOnInit(): void {
    this.loadRecent();
    this.addTerminalLog('Système SOC prêt pour l\'analyse distante.');
  }

  ngAfterViewChecked(): void {
    this.scrollToBottom();
  }

  private scrollToBottom(): void {
    try {
      this.terminalContainer.nativeElement.scrollTop = this.terminalContainer.nativeElement.scrollHeight;
    } catch (err) {}
  }

  addTerminalLog(msg: string): void {
    const time = new Date().toLocaleTimeString();
    this.terminalLogs.push(`[${time}] ${msg}`);
  }

  loadRecent(): void {
    this.recentConnections = this.logService.getRecentConnections();
  }

  fillForm(conn: any): void {
    this.sshForm.patchValue({
      host: conn.host,
      user: conn.user,
      pass: conn.pass,
      filePath: conn.filePath,
      numLines: conn.numLines || 100,
      auditDate: conn.auditDate || conn.specificDate || ''
    });
    this.addTerminalLog(`Configuration chargée pour l'hôte : ${conn.host}`);
  }

  startAnalysis(): void {
    if (this.sshForm.invalid) return;

    this.loading = true;
    this.error = '';
    this.success = false;
    this.terminalLogs = [];
    
    this.addTerminalLog(`WAITING: Tentative de connexion SSH vers ${this.sshForm.value.host}...`);

    this.logService.analyzeSshLog(this.sshForm.value).subscribe({
      next: (response) => {
        this.loading = false;
        if (response?.status === 'success') {
          this.success = true;
          this.lastAnalysisId = response.analysis_id || null;
          this.addTerminalLog(`SUCCESS: Analyse terminée avec succès. ID: ${this.lastAnalysisId}`);
          
          this.logService.saveConnection(this.sshForm.value);
          this.loadRecent();
          return;
        }
        this.error = response?.message || "Erreur lors de l'analyse SSH";
        this.addTerminalLog(`ERROR: ${this.error}`);
      },
      error: (err) => {
        this.loading = false;
        this.error = err.error?.message || "Erreur de connexion au serveur SOC";
        this.addTerminalLog(`ERROR: ${this.error}`);
      }
    });
  }
}
