/** Browser entry point: mount the root Svelte application and global styles. */
import { mount } from 'svelte';
import App from './App.svelte';
import './styles.css';

mount(App, { target: document.getElementById('app')! });
