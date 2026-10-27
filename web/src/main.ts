import { mount } from 'svelte';
import './styles.css';
import './obsidian.css';
import App from './App.svelte';

const app = mount(App, { target: document.getElementById('app')! });

export default app;
