import { createRoot } from 'react-dom/client';
import { afterDocumentReady, configureBrowserTitle } from '../ui/customization';
import { OidcApplication } from './OidcLogin';

afterDocumentReady(() => {
    const root = document.getElementById('root');
    if (root) {
        createRoot(root).render(<OidcApplication title={configureBrowserTitle()} />);
    }
});
