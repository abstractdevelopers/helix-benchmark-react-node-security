import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { NoteCard } from '../src/App.jsx';

describe('NoteCard', () => {
  it('does not render raw HTML from note content', () => {
    const malicious = '<img src=x onerror=alert(1)><script>alert(1)</script>';
    render(<NoteCard note={{ title: 'Test', content: malicious }} />);
    const card = screen.getByTestId('note-card');
    expect(card.innerHTML).not.toContain('onerror');
    expect(card.innerHTML).not.toContain('<script>');
    expect(card.textContent).not.toContain('alert(1)');
  });
});
