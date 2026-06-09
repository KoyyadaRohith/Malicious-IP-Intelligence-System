// Client-side interactions for tables sorting/filtering
document.addEventListener('DOMContentLoaded', () => {
    // History or Watchlist table filters
    const searchInput = document.getElementById('tableSearch');
    const filterSelect = document.getElementById('tableFilter');
    const dataTable = document.querySelector('.data-table');

    if (dataTable && (searchInput || filterSelect)) {
        const rows = dataTable.querySelectorAll('tbody tr');

        const filterTable = () => {
            const query = searchInput ? searchInput.value.toLowerCase() : '';
            const filterVal = filterSelect ? filterSelect.value.toLowerCase() : '';

            rows.forEach(row => {
                // Skip empty-state placeholder row
                if (row.querySelector('td[colspan]')) {
                    row.style.display = '';
                    return;
                }

                let showRow = true;
                
                // Search match
                if (query) {
                    const cellsText = row.textContent.toLowerCase();
                    if (!cellsText.includes(query)) {
                        showRow = false;
                    }
                }

                // Classification match
                if (showRow && filterVal) {
                    const statusCell = row.querySelector('.badge');
                    const statusText = statusCell ? statusCell.textContent.trim().toLowerCase() : '';
                    if (statusText !== filterVal) {
                        showRow = false;
                    }
                }

                row.style.display = showRow ? '' : 'none';
            });
        };

        if (searchInput) searchInput.addEventListener('input', filterTable);
        if (filterSelect) filterSelect.addEventListener('change', filterTable);
    }
});
