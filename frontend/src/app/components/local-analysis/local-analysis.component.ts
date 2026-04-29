import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router, RouterModule } from '@angular/router';
import { LogService } from '../../services/log.service';
import { SidebarComponent } from '../sidebar/sidebar.component';
import { HttpEventType, HttpResponse } from '@angular/common/http';

@Component({
  selector: 'app-local-analysis',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterModule, SidebarComponent],
  templateUrl: './local-analysis.component.html',
  styleUrls: ['./local-analysis.component.css']
})
export class LocalAnalysisComponent {
  selectedFile: File | null = null;
  numLines: number | null = null;
  loading = false;
  error = '';
  isDragging = false;
  progressValue = 0;
  statusMessage = '';
  private processingInterval: any;

  constructor(
    private logService: LogService,
    private router: Router
  ) {}

  onDragOver(event: DragEvent): void {
    event.preventDefault();
    event.stopPropagation();
    this.isDragging = true;
  }

  onDragLeave(event: DragEvent): void {
    event.preventDefault();
    event.stopPropagation();
    this.isDragging = false;
  }

  onDrop(event: DragEvent): void {
    event.preventDefault();
    event.stopPropagation();
    this.isDragging = false;
    
    const files = event.dataTransfer?.files;
    if (files && files.length > 0) {
      this.handleFile(files[0]);
    }
  }

  onFileSelected(event: Event): void {
    const input = event.target as HTMLInputElement;
    if (input.files && input.files.length > 0) {
      this.handleFile(input.files[0]);
    }
  }

  private handleFile(file: File): void {
    const extension = file.name.split('.').pop()?.toLowerCase();
    if (extension === 'log' || extension === 'txt') {
      this.selectedFile = file;
      this.error = '';
    } else {
      this.error = 'Seuls les fichiers .log et .txt sont acceptés.';
      this.selectedFile = null;
    }
  }

  removeFile(event: Event): void {
    event.stopPropagation();
    this.selectedFile = null;
    this.progressValue = 0;
    this.error = '';
  }

  upload(): void {
    if (!this.selectedFile) return;

    this.loading = true;
    this.error = '';
    this.progressValue = 0;
    this.statusMessage = 'Initialisation du transfert...';

    this.logService.uploadLogFile(this.selectedFile, this.numLines).subscribe({
      next: (event: any) => {
        if (event.type === HttpEventType.UploadProgress) {
          const actualProgress = Math.round(90 * event.loaded / event.total);
          this.progressValue = actualProgress;
          this.statusMessage = `Téléchargement : ${actualProgress}%`;
          
          if (actualProgress >= 90) {
            this.startProcessingAnimation();
          }
        } else if (event instanceof HttpResponse) {
          this.completeAnalysis(event.body);
        }
      },
      error: (err) => {
        this.error = err.error?.message || 'Erreur lors de l\'envoi du fichier.';
        this.loading = false;
        this.stopProcessingAnimation();
      }
    });
  }

  private startProcessingAnimation(): void {
    if (this.processingInterval) return;
    
    this.statusMessage = 'Analyse par IA en cours (SOC Gemini)...';
    
    this.processingInterval = setInterval(() => {
      if (this.progressValue < 99) {
        this.progressValue += 1;
      }
    }, 800);
  }

  private completeAnalysis(res: any): void {
    this.stopProcessingAnimation();
    this.progressValue = 100;
    
    if (res.status === 'success' && res.analysis_id) {
      this.statusMessage = 'Analyse terminée ! Redirection...';
      setTimeout(() => {
        this.router.navigate(['/dashboard']);
      }, 1500);
    } else {
      this.error = res.message || 'Erreur lors de l\'analyse.';
      this.loading = false;
    }
  }

  private stopProcessingAnimation(): void {
    if (this.processingInterval) {
      clearInterval(this.processingInterval);
      this.processingInterval = null;
    }
  }
}
