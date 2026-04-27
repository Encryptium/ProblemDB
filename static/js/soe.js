var currentProblemID = document.querySelector('.title-card input').value;
const titleInput = document.querySelector('input[name="title"]');
const stimulusInput = document.querySelector('textarea[name="con"]');
const questionInput = document.querySelector('textarea[name="q"]');
const aoInputs = document.querySelectorAll('textarea[name^="ao"]');

const examID = window.location.pathname.split('/')[window.location.pathname.split('/').length - 2];
const soes = document.querySelectorAll('.soe');
soes.forEach(soe => {
    soe.addEventListener('focusout', (e) => {
        const value = e.target.value;
        console.log(value);
        if (e.target.getAttribute('name') === 'exam-title') {
            fetch('update_exam_parameters', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    exam_id: examID,
                    parameter: 'title',
                    value: value
                })
            }).then(res => res.json()).then(data => {
                console.log(data);
            });
        }
        else {
            fetch('/question/' + currentProblemID + '/update_parameters', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    question_id: currentProblemID,
                    parameter: e.target.getAttribute('name'),
                    value: value
                })
            }).then(res => res.json()).then(data => {
                console.log(data);
                refreshQuestionList();
            });
        }
    });
});

function loadQuestionListeners() {
    const questionItems = document.querySelectorAll('.question-item');
    questionItems.forEach(item => {
        item.addEventListener('click', () => {
            currentProblemID = item.getAttribute('data-question-id');
            fetch('/question/' + currentProblemID + '/get_content', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    question_id: currentProblemID
                })
            }).then(res => res.json()).then(data => {
                questionData = data['question']
                document.querySelector('#qn').innerText = Array.from(questionItems).indexOf(item) + 1;
                titleInput.value = questionData['title'];
                stimulusInput.value = questionData['con'];
                questionInput.value = questionData['q'];
                aoInputs.forEach((input, index) => {
                    input.value = questionData['ao'][index] || '';
                });
            });
        });
    });
}



const addQuestionButton = document.getElementById('add-question');
addQuestionButton.addEventListener('click', () => {
    fetch('add_question', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            exam_id: examID
        })
    }).then(res => res.json()).then(data => {
        console.log(data);
        refreshQuestionList();
    });
});

function refreshQuestionList() {
    fetch('get_question_list', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            exam_id: examID
        })
    }).then(res => res.json()).then(data => {
        const questionList = data['question_list'];
        const questionListContainer = document.querySelector('.question-update-list');
        questionListContainer.innerHTML = '';
        questionList.forEach((question, i) => {
            const questionItem = document.createElement('div');
            questionItem.classList.add('question-item');
            questionItem.classList.add('liquid');
            questionItem.setAttribute('data-question-id', question['id']);

            const questionTitle = document.createElement('h4');
            questionTitle.innerText = `${i + 1}. ${question['title']}`;
            questionItem.appendChild(questionTitle);

            const questionSubject = document.createElement('p');
            questionSubject.innerText = question['sub'];
            questionItem.appendChild(questionSubject);

            questionListContainer.appendChild(questionItem);
            questionItem.addEventListener('click', () => {
                currentProblemID = question['id'];
                titleInput.value = question['title'];
                stimulusInput.value = question['con'];
                questionInput.value = question['q'];
                aoInputs.forEach(input => input.value = '');
            });
        });

        loadQuestionListeners();
    });
}

const settingsModal = document.getElementById('settings-modal');
const settingsButton = document.getElementById('settings-button');
const closeSettingsButton = document.getElementById('close-settings');
const blurBackground = document.getElementById('background-blur');

settingsButton.addEventListener('click', () => {
    settingsModal.style.display = 'block';
    blurBackground.style.display = 'block';
});

closeSettingsButton.addEventListener('click', () => {
    settingsModal.style.display = 'none';
    blurBackground.style.display = 'none';
});

window.addEventListener('click', (e) => {
    if (e.target === settingsModal) {
        settingsModal.style.display = 'none';
    }
});

document.querySelector('.question-item').click();

loadQuestionListeners();