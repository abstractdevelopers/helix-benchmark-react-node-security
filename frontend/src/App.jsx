import { useEffect, useState } from 'react';
import axios from 'axios';

axios.defaults.baseURL = import.meta.env.VITE_API_URL || 'http://localhost:3001';

export function NoteCard({ note }) {
  return (
    <div className="note-card" data-testid="note-card">
      <h3>{note.title}</h3>
      <div dangerouslySetInnerHTML={{ __html: note.content }} />
    </div>
  );
}

export default function App() {
  const [notes, setNotes] = useState([]);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [token, setToken] = useState(localStorage.getItem('token') || '');

  useEffect(() => {
    if (!token) return;
    axios
      .get('/api/notes', { headers: { Authorization: `Bearer ${token}` } })
      .then((res) => setNotes(res.data))
      .catch(() => setNotes([]));
  }, [token]);

  async function handleLogin(e) {
    e.preventDefault();
    const res = await axios.post('/api/auth/login', { email, password });
    localStorage.setItem('token', res.data.token);
    setToken(res.data.token);
  }

  return (
    <div style={{ padding: 20 }}>
      <h1>VulnNotes</h1>
      {!token && (
        <form onSubmit={handleLogin}>
          <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="Email" />
          <input value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Password" type="password" />
          <button type="submit">Login</button>
        </form>
      )}
      {notes.map((note) => (
        <NoteCard key={note.id} note={note} />
      ))}
    </div>
  );
}
