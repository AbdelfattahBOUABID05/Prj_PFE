import { Injectable, Renderer2, RendererFactory2 } from '@angular/core';
import { BehaviorSubject } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class ThemeService {
  private renderer: Renderer2;
  private currentTheme = new BehaviorSubject<'dark' | 'light'>('dark');
  theme$ = this.currentTheme.asObservable();

  constructor(rendererFactory: RendererFactory2) {
    this.renderer = rendererFactory.createRenderer(null, null);
    const savedTheme = localStorage.getItem('theme') as 'dark' | 'light' || 'dark';
    this.setTheme(savedTheme);
  }

  toggleTheme(): void {
    const nextTheme = this.currentTheme.value === 'dark' ? 'light' : 'dark';
    this.setTheme(nextTheme);
  }

  private setTheme(theme: 'dark' | 'light'): void {
    const html = document.documentElement;
    if (theme === 'dark') {
      this.renderer.addClass(html, 'dark');
      this.renderer.removeClass(html, 'light');
    } else {
      this.renderer.addClass(html, 'light');
      this.renderer.removeClass(html, 'dark');
    }
    this.currentTheme.next(theme);
    localStorage.setItem('theme', theme);
  }

  isDark(): boolean {
    return this.currentTheme.value === 'dark';
  }
}
