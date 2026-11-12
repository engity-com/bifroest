import { t } from './messages';

export function ManagementNotFound() {
    return (
        <section className="stack management-not-found" aria-label={t('managementPageNotFound')}>
            <h2>{t('managementPageNotFound')}</h2>
        </section>
    );
}
