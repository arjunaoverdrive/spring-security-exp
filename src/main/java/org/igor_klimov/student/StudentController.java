package org.igor_klimov.student;

import org.igor_klimov.student.Student;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("api/v1/students")
public class StudentController {

    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1, "John Doe"),
            new Student(2, "Mary Johnes"),
            new Student(3, "Mike Smith")
    );

    @GetMapping("{studentId}")
    public Student getStudent(@PathVariable ("studentId") Integer studentId){
        return STUDENTS.stream()
                .filter(s -> studentId.equals(s.getId()))
                .findFirst().orElseThrow(()-> new IllegalStateException("Student " + studentId + "doesn't exist"));
    }
}
