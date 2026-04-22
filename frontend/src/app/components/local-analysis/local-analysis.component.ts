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
  styles: [`
    .drag-over {
      @apply border-indigo-500 bg-indigo-500/5;
    }
    @keyframes progress {
      0% { background-position: 0 0; }
      100% { background-position: 30px 0; }
    }
    .progress-bar-animated {
      background-image: linear-gradient(45deg, rgba(255, 255, 255, 0.15) 25%, transparent 25%, transparent 50%, rgba(255, 255, 255, 0.15) 50%, rgba(255, 255, 255, 0.15) 75%, transparent 75%, transparent);
      background-size: 30px 30px;
      animation: progress 1s linear infinite;
    }
  `]
})
export class LocalAnalysisComponent {
  selectedFile: File | null = null;
  loading = false;
  error = '';
  isDragging = false;
  uploadProgress = 0;
  statusMessage = '';

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
    this.uploadProgress = 0;
    this.error = '';
  }

  upload(): void {
    if (!this.selectedFile) return;

    this.loading = true;
    this.error = '';
    this.uploadProgress = 0;
    this.statusMessage = 'Préparation du fichier...';

    this.logService.uploadLogFile(this.selectedFile).subscribe({
      next: (event: any) => {
        if (event.type === HttpEventType.UploadProgress) {
          this.uploadProgress = Math.round(100 * event.loaded / event.total);
          this.statusMessage = `Téléchargement : ${this.uploadProgress}%`;
        } else if (event instanceof HttpResponse) {
          this.statusMessage = 'Analyse par IA en cours...';
          const res = event.body;
          if (res.status === 'success' && res.analysis_id) {
            setTimeout(() => {
              this.router.navigate(['/dashboard']);
            }, 1500);
          } else {
            this.error = res.message || 'Erreur lors de l\'analyse.';
            this.loading = false;
          }
        }
      },
      error: (err) => {
        this.loading = false;
        this.uploadProgress = 0;
        this.error = err.error?.message || 'Une erreur est survenue lors de l\'envoi du fichier.';
        console.error('Upload error:', err);
      }
    });
  }
}
