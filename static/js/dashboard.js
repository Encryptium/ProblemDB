const previewButtons = document.querySelectorAll('.preview');
const deleteButtons = document.querySelectorAll('.delete');

previewButtons.forEach(button => {
    button.addEventListener('click', (e) => {
        e.stopPropagation();
        const examID = button.closest('.exam-card').getAttribute('data-exam-id');
        window.open('/exam/' + examID + '/preview', '_blank');
    });
});

deleteButtons.forEach(button => {
    button.addEventListener('click', (e) => {
        e.stopPropagation();
        const examID = button.closest('.exam-card').getAttribute('data-exam-id');
        if (confirm('Are you sure you want to delete this exam?')) {
            fetch('/exam/' + examID + '/delete', {
                method: 'GET',
            }).then(res => res.json()).then(data => {
                if (data['success']) {
                    location.reload();
                } else {
                    alert('Failed to delete exam.');
                }
            });
        }
    });
});