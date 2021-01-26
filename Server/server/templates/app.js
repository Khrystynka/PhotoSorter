const input = document.querySelector('#file');
const preview = document.querySelector('.preview');


// input.style.opacity = 0;
input.addEventListener('change', updateImageDisplay);
function updateImageDisplay() {
    console.log(input.value)
    while(preview.firstChild) {
      preview.removeChild(preview.firstChild);
    }
  
    const curFiles = input.files;
    if(curFiles.length === 0) {
      const paragraph = document.createElement('p');
      paragraph.textContent = 'No files currently selected for upload';
      preview.appendChild(paragraph);
    } else {
      const list = document.createElement('ol');
      preview.appendChild(list);
  
      for(const file of curFiles) {
        const listItem = document.createElement('li');
        const paragraph = document.createElement('p');
        // if(validFileType(file)) {
          paragraph.textContent = `File name ${file.name}`;
          const image = document.createElement('img');
          const fileURL = URL.createObjectURL(file)
          image.src = fileURL;

          console.log('windowURL',window.URL);
          console.log('fileURL',fileURL)
          console.log('inputValue',input.value)

        //   image.style.objectFit="contain"
        //   image.style.height='200px'
        //   image.style.width= '200px'
        //   image.style.border="1px solid "
  
          listItem.appendChild(paragraph);
          listItem.appendChild(image);

        // // } else {
        //   para.textContent = `File name ${file.name}: Not a valid file type. Update your selection.`;
        //   listItem.appendChild(para);
        // }
  
        list.appendChild(listItem);
      }
    }
  }
  