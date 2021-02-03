// import axios from 'axios'
const input = document.querySelector('#file');
const preview = document.querySelector('.preview');
const tagListURL = 'http://127.0.0.1:5000/get_tags'
let tag_options=[]
console.log('cookies',document.cookie)
cookie= {session:1234}
axios.get(tagListURL,{withCredentials: true})
.then(data=>{
  tag_options = data.data
})
.catch(err=>console.log('err',err))

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
      console.log('All files',curFiles)
      console.log(typeof(curFiles))
      // for(const [index,file] of curFiles.entries()) {
      for (let i=0;i<curFiles.length;i++){
        file = curFiles[i]
        console.log(i,file)
        const listItem = document.createElement('li');
        const paragraph = document.createElement('p');
        const tag_label = document.createElement('label')
        tag_label.setAttribute('for','tag_input')
        tag_label.textContent = 'Add tags'

        // <label for="ice-cream-choice">Choose a flavor:</label>

        const tag_input = document.createElement('input')
        tag_input.setAttribute('type','text')
        tag_input.setAttribute('list','tags')
        tag_input.setAttribute('id','tag_input')
        tag_input.setAttribute('name',`tag${i}`)
        console.log(`tag${i}`)

        const data_list = document.createElement('datalist')
        data_list.id='tags'
        len = tag_options.length
        for (let i=0 ; i < len; i += 1) {
            var option = document.createElement('option');
            option.value = tag_options[i];
            data_list.appendChild(option);
        }    
        tag_input.appendChild(data_list)
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
          listItem.appendChild(tag_label)
          listItem.appendChild(tag_input)


        // // } else {
        //   para.textContent = `File name ${file.name}: Not a valid file type. Update your selection.`;
        //   listItem.appendChild(para);
        // }
  
        list.appendChild(listItem);
      }
    }
  }
  