const { Router } = require('express');
const express = require('express');
const router = express.Router();
const fetchuser = require('../middleware/fetchuser');
const Note = require('../models/Note')
const { body, validationResult } = require('express-validator');

// ROUTE 1 : Get all the notes: GET endpoint:"api/note/fetchallnotes"
router.get('/fetchallnotes',fetchuser, async (req,res)=>{
    try {
        const notes = await Note.find({user:req.user.id});
        res.json(notes);
    }catch (error) {
        console.log(error.message);
        res.status(500).send("Internal server error");
    }
    
})

// ROUTE 2 : Add new notes: POST endpoint:"/api/note/addnote"
router.post('/addnote',fetchuser, [ 
    body('title','Enter a valid title').isLength({ min: 3 }),
    body('description','description must be atleast 5 characters').isLength({ min: 5 }),], async (req,res)=>
    {
        try{
            const {title, description, tag} = req.body;
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
            }

            const note = new Note({
                title, description, tag, user:req.user.id
            })

            const savedNote = await note.save()

            res.json(savedNote);

             
        } catch (error) {
            console.log(error.message);
            res.status(500).send("Internal server error");
        }
})

// ROUTE 3 : Update existing notes: PUT "/api/notes/updatenote"
router.put('/updatenote/:id',fetchuser,async (req,res)=>{
    const {title,description,tag} = req.body;

    const newNote = {};
    if(title) {newNote.title = title};
    if(description) {newNote.description = description};
    if(tag) {newNote.tag = tag};


    //Find the note to be updated and update it
    let note = await Note.findById(req.params.id);
    if(!note){return res.send(404).send("Not found")}

    if(note.user.toString() !== req.user.id){
        return res.status(401).send("Not allowed");
    }

    note = await Note.findByIdAndUpdate(req.params.id,{$set:newNote},{new:true});  //new:true will create a new content when it doesn't exist
    res.json({note});
})


// ROUTE 4: Delete an existing Note using: DELETE "/api/notes/deletenote"
router.delete('/deletenote/:id', fetchuser, async (req, res) => {
    try {
        // Find the note to be delete and delete it
        let note = await Note.findById(req.params.id);
        if (!note) { return res.status(404).send("Not Found") }

        // Allow deletion only if user owns this Note
        if (note.user.toString() !== req.user.id) {
            return res.status(401).send("Not Allowed");
        }

        note = await Note.findByIdAndDelete(req.params.id)
        res.json({ "Success": "Note has been deleted", note: note });
    } catch (error) {
        console.error(error.message);
        res.status(500).send("Internal Server Error");
    }
})
module.exports =  router        